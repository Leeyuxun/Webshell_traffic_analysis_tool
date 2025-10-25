#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import struct
import binascii
import json

def decrypt_and_parse(data: bytes) -> dict:
    """
    Decrypts and parses a single suo5 data blob.
    It first tries to parse the decrypted data as suo5's key-value structure.
    If that fails, it assumes the data is raw and returns it as text or hex.
    This handles both structured requests/responses and raw data responses.
    """
    if len(data) < 5:
        return {"error": "Encrypted data is too short (less than 5 bytes)."}
    try:
        data_len = struct.unpack('>I', data[:4])[0]
        xor_key = data[4]
        
        if len(data) < 5 + data_len:
            return {"error": f"Incomplete data: Expected {data_len} payload bytes, have {len(data) - 5}."}
        
        encrypted_payload = data[5:5 + data_len]
        decrypted_payload = bytes([b ^ xor_key for b in encrypted_payload])

        # Attempt to parse as key-value structure first
        try:
            parsed_data, offset = {}, 0
            while offset < len(decrypted_payload):
                if offset + 1 > len(decrypted_payload):
                    break
                
                key_len = decrypted_payload[offset]
                offset += 1
                
                if offset + key_len > len(decrypted_payload):
                    raise ValueError("Incomplete key")
                key = decrypted_payload[offset:offset + key_len].decode('utf-8', 'ignore')
                offset += key_len
                
                if offset + 4 > len(decrypted_payload):
                    raise ValueError("Incomplete value length")
                value_len = struct.unpack('>I', decrypted_payload[offset:offset + 4])[0]
                offset += 4

                if offset + value_len > len(decrypted_payload):
                    raise ValueError("Incomplete value")
                value = decrypted_payload[offset:offset + value_len]
                offset += value_len
                parsed_data[key] = value
            
            # If we successfully parsed, decode values to string where possible
            for k, v in parsed_data.items():
                try:
                    parsed_data[k] = v.decode('utf-8')
                except UnicodeDecodeError:
                    parsed_data[k] = v.hex()
            return parsed_data
        
        except (ValueError, struct.error):
            # If parsing as key-value fails, treat as raw data.
            # This is common for response payloads containing arbitrary TCP stream data.
            try:
                # Try to decode as a simple string, ignoring errors for binary data
                return {"decoded_as_text": decrypted_payload.decode('utf-8', 'ignore')}
            except Exception:
                # If all else fails, return hex
                return {"raw_hex_data": decrypted_payload.hex()}
        
    except (struct.error, ValueError) as e:
        # This catches errors in the initial decryption (length/key read)
        return {"error": f"Decryption failed during initial unpacking: {e}"}

def decrypt_hex_string(payload_hex: str) -> str:
    """
    Takes a hex string, handles potential chunked encoding, decrypts it,
    and returns a formatted JSON string of the result.
    """
    payload_hex = payload_hex.strip()
    status_updates = []

    # Automatically detect and strip HTTP chunk metadata if present.
    try:
        crlf_pos = payload_hex.index("0d0a")
        chunk_size_hex = payload_hex[:crlf_pos]
        int(chunk_size_hex, 16)
        status_updates.append("[*] HTTP chunk metadata detected. Stripping it before decryption.")
        payload_hex = payload_hex[crlf_pos + 4:]
        if payload_hex.endswith("0d0a"):
            payload_hex = payload_hex[:-4]
    except (ValueError, IndexError):
        pass

    try:
        encrypted_data = binascii.unhexlify(payload_hex)
    except binascii.Error:
        return "[!] Error: Invalid hexadecimal string provided."

    decrypted_data = decrypt_and_parse(encrypted_data)
    
    # Prepend status updates to the final result
    status_str = "\n".join(status_updates)
    result_str = json.dumps(decrypted_data, indent=2, ensure_ascii=False)
    
    if status_str:
        return f"{status_str}\n\n{result_str}"
    return result_str

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt a suo5 encrypted request or response body.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Example:
  python3 decrypt_suo5_payload.py 0000001859026163013002696408715463654136374601680b3132322e31362e34362e343801700436333739
"""
    )
    parser.add_argument("payload", help="The encrypted payload as a single hexadecimal string.")
    args = parser.parse_args()

    result_string = decrypt_hex_string(args.payload)
    print(result_string)

if __name__ == "__main__":
    main() 