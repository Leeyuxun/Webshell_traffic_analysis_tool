#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP, Raw
import openpyxl
from decrypt_behinder_payload import get_session_key, decrypt_first_response, decrypt_subsequent_payload

def analyze_behinder_sessions(packets, password: str, status_callback):
    """
    Analyzes a pcap file for Behinder webshell traffic, handles dynamic key exchange.
    """
    # Group packets by TCP stream
    sessions = defaultdict(list)
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            stream_key = tuple(sorted(((packet[IP].src, packet[TCP].sport), (packet[IP].dst, packet[TCP].dport))))
            sessions[stream_key].append(packet)

    results = []
    initial_key = get_session_key(password)
    status_callback(f"[*] Analyzing {len(sessions)} TCP streams with initial key...")

    for stream_key, stream_packets in sessions.items():
        if not stream_packets:
            continue
            
        # Sort packets by time to ensure correct order
        stream_packets.sort(key=lambda p: p.time)
        
        server_ip, server_port = None, None
        dynamic_key = None
        
        # Try to find the handshake (first non-empty request and response)
        for i, packet in enumerate(stream_packets):
            if not packet.haslayer(Raw) or not packet[Raw].load:
                continue

            # Identify request and response based on HTTP method
            payload_bytes = packet[Raw].load
            if payload_bytes.startswith(b'POST'):
                # This is a request, look for the corresponding response
                if i + 1 < len(stream_packets):
                    response_packet = stream_packets[i+1]
                    if response_packet.haslayer(Raw) and response_packet[Raw].load:
                        res_header_end = response_packet[Raw].load.find(b'\r\n\r\n')
                        if res_header_end != -1:
                            res_body = response_packet[Raw].load[res_header_end + 4:]
                            dynamic_key = decrypt_first_response(res_body, initial_key)
                            
                            if dynamic_key:
                                server_ip = response_packet[IP].src
                                server_port = response_packet[TCP].sport
                                status_callback(f"[+] Handshake successful for stream {stream_key}! Dynamic key found.")
                                break # Handshake complete

        if not dynamic_key:
            continue # Could not establish a dynamic key for this stream

        # Decrypt subsequent traffic with the dynamic key
        for packet in stream_packets:
            try:
                if not packet.haslayer(Raw) or not packet[Raw].load:
                    continue
                
                direction = ""
                if packet[IP].dst == server_ip and packet[TCP].dport == server_port:
                    direction = "Request (Client -> Server)"
                elif packet[IP].src == server_ip and packet[TCP].sport == server_port:
                    direction = "Response (Server -> Client)"
                else:
                    continue # Not part of this directed conversation

                body_start = packet[Raw].load.find(b'\r\n\r\n')
                if body_start == -1:
                    continue
                
                encrypted_body = packet[Raw].load[body_start + 4:]
                if not encrypted_body:
                    continue

                decrypted_content = decrypt_subsequent_payload(encrypted_body, dynamic_key)

                # Skip handshake packets and empty results
                if decrypted_content.strip() and "Content-Type" not in decrypted_content:
                    results.append({
                        "timestamp": float(packet.time),
                        "stream_info": f"{stream_key[0][0]}:{stream_key[0][1]} <-> {stream_key[1][0]}:{stream_key[1][1]}",
                        "direction": direction,
                        "content": decrypted_content,
                    })
            except Exception:
                continue # Ignore packets that fail to decrypt

    return results

def write_behinder_results_to_excel(analysis_results, output_path):
    """Writes the Behinder analysis results to an Excel file."""
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Behinder Analysis"
    
    headers = ['时间戳', 'TCP流', '方向', '解密后内容']
    sheet.append(headers)
    
    # Sort results by timestamp before writing
    analysis_results.sort(key=lambda x: x['timestamp'])

    for result in analysis_results:
        sheet.append([
            result.get('timestamp', 'N/A'),
            result.get('stream_info', 'N/A'),
            result.get('direction', 'N/A'),
            result.get('content', 'N/A'),
        ])
    
    workbook.save(output_path)

def process_behinder_pcap(input_path, output_path, password, status_callback=print):
    """Main processing function for Behinder PCAP analysis."""
    try:
        status_callback(f"[*] Reading raw PCAP file '{input_path}'...")
        all_packets = rdpcap(input_path)
        status_callback(f"[*] Total packets read: {len(all_packets)}")
        
        if not all_packets:
            status_callback("[!] PCAP file is empty or could not be read.")
            return

        analysis_results = analyze_behinder_sessions(all_packets, password, status_callback)
        
        if not analysis_results:
            status_callback("[!] No valid Behinder traffic could be decrypted. Check your password.")
            return

        write_behinder_results_to_excel(analysis_results, output_path)
        status_callback(f"\n[*] Successfully analyzed and decrypted {len(analysis_results)} interactions.")
        status_callback(f"[*] Behinder analysis report saved to '{output_path}'.")

    except Exception as e:
        status_callback(f"[!] An unexpected error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP file for Behinder webshell traffic (v3/v4).")
    parser.add_argument("-i", "--input", required=True, help="Path to the input PCAP file.")
    parser.add_argument("-o", "--output", required=True, help="Path to save the output Excel file.")
    parser.add_argument("-p", "--password", required=True, help="The connection password for the webshell.")
    args = parser.parse_args()
    
    process_behinder_pcap(args.input, args.output, args.password)

if __name__ == "__main__":
    main() 