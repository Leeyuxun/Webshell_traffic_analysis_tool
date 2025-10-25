#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import struct
import binascii
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP, Raw

try:
    import openpyxl
except ImportError:
    print("[!] The 'openpyxl' library is required to generate Excel reports.", file=sys.stderr)
    print("[!] Please install it using: pip install openpyxl", file=sys.stderr)
    sys.exit(1)

# --- Constants and Feature Definitions (from extract_suo5.py) ---
SUO5_DEFAULT_USER_AGENT = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.1.2.3"
SUO5_ACCEL_BUFFERING_HEADER = "X-Accel-Buffering: no"

# --- Filtering Logic (from extract_suo5.py) ---

def is_http_packet(packet):
    """Check if a packet is likely HTTP."""
    if packet.haslayer(TCP):
        # A simple check for HTTP ports or payload content
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            return True
        if packet.haslayer(Raw) and b"HTTP/" in packet[Raw].load:
            return True
    return False

def check_suo5_indicators(packet):
    """Checks a packet for suo5 indicators."""
    if not is_http_packet(packet) or not packet.haslayer(Raw):
        return False
    try:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if SUO5_DEFAULT_USER_AGENT in payload:
            return True
        if SUO5_ACCEL_BUFFERING_HEADER.lower() in payload.lower():
            return True
    except (UnicodeDecodeError, AttributeError):
        return False
    return False

def filter_suo5_packets_in_memory(packets):
    """
    Analyzes a list of packets, identifies suo5 sessions, 
    and returns a new list containing only packets from those sessions.
    """
    print("[*] Phase 1: Filtering for suo5 indicators...")
    suo5_sessions = set()
    
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            session_key_forward = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
            session_key_reverse = (packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport)

            if session_key_forward in suo5_sessions:
                continue

            if check_suo5_indicators(packet):
                print(f"[+] Found suo5 indicator in packet: {packet.summary()}")
                suo5_sessions.add(session_key_forward)
                suo5_sessions.add(session_key_reverse)

    if not suo5_sessions:
        print("[-] No suo5 traffic found based on indicators.")
        return []
        
    print(f"\n[+] Identified {len(suo5_sessions) // 2} potential suo5 session(s).")
    
    filtered_packets = [
        p for p in packets 
        if p.haslayer(IP) and p.haslayer(TCP) and (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport) in suo5_sessions
    ]
    
    print(f"[*] Extracted {len(filtered_packets)} packets for deep analysis.")
    return filtered_packets

# --- Decryption and Analysis Logic (from pcap_suo5_analyzer.py) ---

def decrypt_and_parse(data: bytes) -> dict:
    if len(data) < 5: return {"error": "Encrypted data is too short (less than 5 bytes)."}
    try:
        data_len = struct.unpack('>I', data[:4])[0]
        xor_key = data[4]
        if len(data) < 5 + data_len: return {"error": f"Incomplete data: Expected {data_len} payload bytes, have {len(data) - 5}."}
        
        encrypted_payload = data[5:5 + data_len]
        decrypted_payload = bytes([b ^ xor_key for b in encrypted_payload])

        parsed_data, offset = {}, 0
        while offset < len(decrypted_payload):
            if offset + 1 > len(decrypted_payload): break
            key_len = decrypted_payload[offset]; offset += 1
            if offset + key_len > len(decrypted_payload): raise ValueError("Incomplete key")
            key = decrypted_payload[offset:offset + key_len].decode('utf-8', 'ignore'); offset += key_len
            if offset + 4 > len(decrypted_payload): raise ValueError("Incomplete value length")
            value_len = struct.unpack('>I', decrypted_payload[offset:offset + 4])[0]; offset += 4
            if offset + value_len > len(decrypted_payload): raise ValueError("Incomplete value")
            value = decrypted_payload[offset:offset + value_len]; offset += value_len
            parsed_data[key] = value
        
        for k, v in parsed_data.items():
            try: parsed_data[k] = v.decode('utf-8')
            except UnicodeDecodeError: parsed_data[k] = v.hex()
        return parsed_data
    except (struct.error, ValueError) as e:
        return {"error": f"Decryption/parsing failed: {e}"}

def analyze_http_body(body: bytes, headers: str) -> list:
    decrypted_payloads = []
    if 'transfer-encoding: chunked' in headers:
        offset = 0
        while offset < len(body):
            crlf_pos = body.find(b'\r\n', offset)
            if crlf_pos == -1: break
            chunk_size_hex = body[offset:crlf_pos]
            if not chunk_size_hex: break
            try: chunk_size = int(chunk_size_hex, 16)
            except ValueError: break
            if chunk_size == 0: break
            data_start = crlf_pos + 2
            chunk_data = body[data_start : data_start + chunk_size]
            decrypted_payloads.append(decrypt_and_parse(chunk_data))
            offset = data_start + chunk_size + 2
    elif body:
         decrypted_payloads.append(decrypt_and_parse(body))
    return decrypted_payloads

def sort_dict_keys(d: dict, key_order: list) -> dict:
    sorted_dict = {key: d[key] for key in key_order if key in d}
    sorted_dict.update({key: val for key, val in d.items() if key not in sorted_dict})
    return sorted_dict

def build_tcp_stream_index_map(packets, base_time):
    """
    Builds a map from TCP session keys to a Wireshark-like stream index
    and a map to the timestamp of the first packet in each stream.
    """
    print("[*] Building TCP stream index and timestamp maps...")
    stream_map = {}
    stream_timestamps = {}
    stream_index = 0
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            stream_key = tuple(sorted(((packet[IP].src, packet[TCP].sport), (packet[IP].dst, packet[TCP].dport))))
            if stream_key not in stream_map:
                stream_map[stream_key] = stream_index
                stream_timestamps[stream_key] = packet.time - base_time
                stream_index += 1
    print(f"[*] Found {len(stream_map)} unique TCP streams in the pcap.")
    return stream_map, stream_timestamps

def analyze_sessions(packets, stream_map, stream_timestamps):
    print("\n[*] Phase 2: Reassembling and analyzing TCP streams...")
    sessions = defaultdict(lambda: defaultdict(bytes))

    for packet in packets:
        if not packet.haslayer(Raw):
            continue
        ip, tcp = packet[IP], packet[TCP]
        stream_key = tuple(sorted(((ip.src, tcp.sport), (ip.dst, tcp.dport))))
        
        direction_key = ((ip.src, tcp.sport), (ip.dst, tcp.dport))
        sessions[stream_key][direction_key] += packet[Raw].load

    print(f"[*] Found {len(sessions)} unique TCP streams for analysis. Processing...")
    results = []
    for stream_index, (stream_key, directions) in enumerate(sessions.items()):
        wireshark_stream_index = stream_map.get(stream_key, -1) # Default to -1 if somehow not found
        stream_info_str = f"{stream_key[0][0]}:{stream_key[0][1]} <-> {stream_key[1][0]}:{stream_key[1][1]}"
        
        first_packet_ts = stream_timestamps.get(stream_key)
        # Use the raw float timestamp from scapy, which is Wireshark-compatible (Unix epoch time)
        timestamp = float(first_packet_ts) if first_packet_ts is not None else "N/A"

        if len(directions) != 2:
            print(f"[-] Skipping stream (wireshark_idx={wireshark_stream_index}, {stream_info_str}): Not a bidirectional stream.")
            continue
        
        flow1_data, flow2_data = directions.values()
        request_data, response_data = None, None

        # Try to identify client (request) and server (response) flows based on HTTP methods
        if flow1_data.startswith((b'POST ', b'GET ', b'OPTIONS ')):
            request_data, response_data = flow1_data, flow2_data
        elif flow2_data.startswith((b'POST ', b'GET ', b'OPTIONS ')):
            request_data, response_data = flow2_data, flow1_data
        else:
            # If no standard HTTP method is found, we don't skip. Instead, we attempt raw analysis.
            # This is crucial for suo5 as subsequent traffic in a tunnel may not look like HTTP.
            print(f"[*] Stream (wireshark_idx={wireshark_stream_index}, {stream_info_str}): Not a standard HTTP start. Attempting raw TCP analysis by assuming flow direction.")
            # We make a default assignment and let the decryption logic sort it out.
            request_data, response_data = flow1_data, flow2_data

        req_header_end = request_data.find(b'\r\n\r\n')
        res_header_end = response_data.find(b'\r\n\r\n')
        req_body = request_data[req_header_end + 4:] if req_header_end != -1 else b''
        res_body = response_data[res_header_end + 4:] if res_header_end != -1 else b''

        if 32 <= len(req_body) <= 1024 and len(res_body) == 32 and res_body == req_body[:32]:
            results.append({
                "tcp_stream_index": wireshark_stream_index, 
                "timestamp": timestamp,
                "stream_info": stream_info_str, 
                "decrypted_requests": [{"status": "Connectivity Check"}], 
                "decrypted_responses": [{"status": "Connectivity Check Response"}]
            })
            continue
        
        decrypted_requests, decrypted_responses = [], []
        if req_header_end != -1: decrypted_requests = analyze_http_body(req_body, request_data[:req_header_end].decode('utf-8', 'ignore').lower())
        if res_header_end != -1: decrypted_responses = analyze_http_body(res_body, response_data[:res_header_end].decode('utf-8', 'ignore').lower())

        if decrypted_requests or decrypted_responses:
            target_address = None
            for req in decrypted_requests:
                # The 'ac' (action) for connection is '\u0000' (null byte), not 'conn'.
                if isinstance(req, dict) and req.get('ac') == '\u0000' and 'h' in req and 'p' in req:
                    host, port = req.get('h'), req.get('p')
                    if isinstance(host, str) and isinstance(port, str):
                        target_address = f"{host}:{port}"
                        break
            
            sorted_reqs = [sort_dict_keys(req, ['ac', 'id', 'h', 'p', 'dt']) for req in decrypted_requests]
            sorted_resps = [sort_dict_keys(res, ['s', 'ac', 'dt']) for res in decrypted_responses]
            
            result_item = {
                "tcp_stream_index": wireshark_stream_index,
                "timestamp": timestamp,
                "stream_info": stream_info_str,
                "decrypted_requests": sorted_reqs,
                "decrypted_responses": sorted_resps
            }
            if target_address:
                result_item["target"] = target_address
            results.append(result_item)
        else:
            print(f"[-] Skipping stream (wireshark_idx={wireshark_stream_index}, {stream_info_str}): Identified as HTTP but no valid suo5 payloads found after analysis.")
            
    return results

def write_results_to_excel(analysis_results, output_path):
    """Writes the analysis results to an Excel file."""
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "suo5 Analysis"
    
    headers = ['TCP流(不准确，请参考时间戳)', '时间戳', '流量信息', '目标地址', '请求命令', '响应内容']
    sheet.append(headers)
    
    row_count = 0
    for result in analysis_results:
        requests = result.get('decrypted_requests', [])
        responses = result.get('decrypted_responses', [])

        # Common info for all rows from this stream
        base_info = [
            result.get('tcp_stream_index', 'N/A'),
            result.get('timestamp', 'N/A'),
            result.get('stream_info', 'N/A'),
            result.get('target', 'N/A')
        ]
        
        # Handle requests, even if they don't have a corresponding response.
        num_requests = len(requests)
        num_responses = len(responses)

        for i in range(num_requests):
            req = requests[i]
            # Get corresponding response if it exists, otherwise use an empty dict.
            resp = responses[i] if i < num_responses else {}
            
            # Skip non-dict entries (like connectivity checks) and connection setup packets
            if not isinstance(req, dict) or req.get('ac') == '\u0000':
                continue
                
            # We are only interested in actual commands which have a 'dt' field.
            if 'dt' in req:
                command = req.get('dt', '').strip()
                response_data = resp.get('dt', '').strip()
                
                # Create a new row for each command
                row_data = base_info + [command, response_data]
                sheet.append(row_data)
                row_count += 1
                
    if row_count > 0:
        print(f"\n[*] Wrote {row_count} command entries to Excel.")
        workbook.save(output_path)
    else:
        print("\n[!] No valid command entries were found to write to the Excel file.")

def process_pcap_to_excel(input_path, output_path, status_callback=print):
    """
    Analyzes a pcap file and writes the results to an excel file.
    This function can be called from other scripts, like a GUI.
    The status_callback function is used to report progress.
    """
    try:
        status_callback(f"[*] Reading raw PCAP file '{input_path}'...")
        all_packets = rdpcap(input_path)
        status_callback(f"[*] Total packets read: {len(all_packets)}")

        if not all_packets:
            status_callback("[!] PCAP file is empty or could not be read.")
            return

        base_time = all_packets[0].time
        
        status_callback("[*] Building TCP stream index and timestamp maps...")
        tcp_stream_map, tcp_stream_timestamps = build_tcp_stream_index_map(all_packets, base_time)
        status_callback(f"[*] Found {len(tcp_stream_map)} unique TCP streams in the pcap.")
        
        status_callback("[*] Phase 1: Filtering for suo5 indicators...")
        suo5_packets = filter_suo5_packets_in_memory(all_packets)
        
        if not suo5_packets:
            status_callback("[!] No suo5 packets were found to analyze.")
            return
        status_callback(f"[*] Extracted {len(suo5_packets)} packets for deep analysis.")

        status_callback("\n[*] Phase 2: Reassembling and analyzing TCP streams...")
        analysis_results = analyze_sessions(suo5_packets, tcp_stream_map, tcp_stream_timestamps)
        
        if not analysis_results:
            status_callback("[!] No valid suo5 streams could be fully analyzed.")
            return

        write_results_to_excel(analysis_results, output_path)
            
        status_callback(f"\n[*] Successfully analyzed {len(analysis_results)} streams.")
        status_callback(f"[*] Full analysis report saved to '{output_path}'.")
    except Exception as e:
        status_callback(f"[!] An unexpected error occurred: {e}")

# --- Main Execution Logic ---

def main():
    parser = argparse.ArgumentParser(description="A full-pipeline analyzer for suo5 traffic. Extracts, decrypts, and analyzes from a single PCAP file.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--input', required=True, help="Path to the raw input PCAP file (e.g., attack.pcap).")
    parser.add_argument('-o', '--output', required=True, help="Path to save the final analysis Excel file (e.g., report.xlsx).")
    args = parser.parse_args()
    
    try:
        process_pcap_to_excel(args.input, args.output)
    except FileNotFoundError:
        print(f"[!] Error: Input file not found at '{args.input}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 