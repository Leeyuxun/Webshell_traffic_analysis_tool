#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from collections import defaultdict
from urllib.parse import unquote

from scapy.all import rdpcap, TCP, IP, Raw
import openpyxl

# Import the main dispatcher function and specific decrypters for response handling
from decrypt_godzilla_payload import godzilla_decode, decrypt_aes_base64, decrypt_xor_base64

def analyze_godzilla_sessions(packets, key: str, uri: str, crypter: str, status_callback):
    """Reassembles and analyzes TCP streams for Godzilla traffic."""
    sessions = defaultdict(lambda: defaultdict(bytes))
    
    # First, identify sessions that contain a POST request to the specified URI
    godzilla_session_keys = set()
    post_string = f"POST {uri}".encode()
    status_callback("[*] Phase 1: Identifying potential Godzilla sessions...")

    for packet in packets:
        if packet.haslayer(Raw) and post_string in packet[Raw].load:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                session_key = tuple(sorted(((packet[IP].src, packet[TCP].sport), (packet[IP].dst, packet[TCP].dport))))
                godzilla_session_keys.add(session_key)

    if not godzilla_session_keys:
        status_callback("[-] No sessions found with POST requests to the specified URI.")
        return []
    
    status_callback(f"[+] Found {len(godzilla_session_keys)} potential Godzilla session(s). Reassembling...")

    # Reassemble only the identified sessions
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            stream_key = tuple(sorted(((packet[IP].src, packet[TCP].sport), (packet[IP].dst, packet[TCP].dport))))
            if stream_key in godzilla_session_keys:
                direction_key = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
                if packet.haslayer(Raw):
                    sessions[stream_key][direction_key] += packet[Raw].load

    results = []
    status_callback("\n[*] Phase 2: Decrypting and analyzing reassembled streams...")
    
    for stream_key, directions in sessions.items():
        if len(directions) < 2:
            continue

        flow1_data, flow2_data = directions.values()
        
        # Identify request and response
        if post_string in flow1_data:
            request_data, response_data = flow1_data, flow2_data
        elif post_string in flow2_data:
            request_data, response_data = flow2_data, flow1_data
        else:
            continue

        req_header_end = request_data.find(b'\r\n\r\n')
        res_header_end = response_data.find(b'\r\n\r\n')
        
        req_body = request_data[req_header_end + 4:] if req_header_end != -1 else b''
        res_body = response_data[res_header_end + 4:] if res_header_end != -1 else b''

        if not req_body:
            continue
            
        req_body_str = unquote(req_body.decode('utf-8', 'ignore'))
        
        # For EVAL crypter, the entire body is the payload. 
        # For others, we extract the value from the first parameter.
        if 'EVAL' in crypter:
            payload_to_decode = req_body_str
        else:
            try:
                payload_to_decode = req_body_str.split('=', 1)[1]
            except IndexError:
                continue # Skip if payload format is invalid
        
        decrypted_request = godzilla_decode(payload_to_decode, key, crypter)
        
        # --- Response Decryption ---
        decrypted_response = ""
        if res_body:
            response_payload_b64 = res_body.decode('utf-8', 'ignore')
            if 'AES' in crypter:
                decrypted_response = decrypt_aes_base64(response_payload_b64, key)
            elif 'XOR' in crypter:
                # XOR responses are framed with MD5 hashes
                if len(res_body) > 32:
                    response_payload_b64 = res_body[16:-16].decode('utf-8', 'ignore')
                    decrypted_response = decrypt_xor_base64(response_payload_b64, key)
                else:
                    decrypted_response = "[!] Invalid XOR response format (too short)."
            else:
                decrypted_response = "[!] Unknown response encryption type."
        else:
            decrypted_response = "[!] No response body found."
        
        results.append({
            "stream_info": f"{stream_key[0][0]}:{stream_key[0][1]} <-> {stream_key[1][0]}:{stream_key[1][1]}",
            "request": decrypted_request,
            "response": decrypted_response,
        })
        
    return results

def write_godzilla_results_to_excel(analysis_results, output_path):
    """Writes the Godzilla analysis results to an Excel file."""
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Godzilla Analysis"
    
    headers = ['流量信息', '解密后请求', '解密后响应']
    sheet.append(headers)
    
    for result in analysis_results:
        sheet.append([
            result.get('stream_info', 'N/A'),
            result.get('request', 'N/A'),
            result.get('response', 'N/A'),
        ])
    
    workbook.save(output_path)

def process_godzilla_pcap(input_path, output_path, key, uri, crypter, status_callback=print):
    """Main processing function for Godzilla PCAP analysis."""
    try:
        status_callback(f"[*] Reading raw PCAP file '{input_path}'...")
        all_packets = rdpcap(input_path)
        status_callback(f"[*] Total packets read: {len(all_packets)}")
        
        if not all_packets:
            status_callback("[!] PCAP file is empty or could not be read.")
            return

        analysis_results = analyze_godzilla_sessions(all_packets, key, uri, crypter, status_callback)
        
        if not analysis_results:
            status_callback("[!] No valid Godzilla traffic could be decrypted. Check your key, URI and selected crypter.")
            return

        write_godzilla_results_to_excel(analysis_results, output_path)
        status_callback(f"\n[*] Successfully analyzed and decrypted {len(analysis_results)} interactions.")
        status_callback(f"[*] Godzilla analysis report saved to '{output_path}'.")

    except Exception as e:
        status_callback(f"[!] An unexpected error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP file for Godzilla webshell traffic.")
    parser.add_argument("-i", "--input", required=True, help="Path to the input PCAP file.")
    parser.add_argument("-o", "--output", required=True, help="Path to save the output Excel file.")
    parser.add_argument("-k", "--key", required=True, help="The connection password (key) for the webshell.")
    parser.add_argument("-u", "--uri", required=True, help="The URI of the webshell endpoint (e.g., '/shell.jsp').")
    parser.add_argument(
        "-c", "--crypter",
        required=True,
        choices=['AES_BASE64 (V4 Default)', 'XOR_BASE64 (V3 Default)', 'PHP_EVAL_XOR_BASE64'],
        help="The crypter used by the Godzilla shell."
    )
    args = parser.parse_args()
    
    process_godzilla_pcap(args.input, args.output, args.key, args.uri, args.crypter)

if __name__ == "__main__":
    main() 