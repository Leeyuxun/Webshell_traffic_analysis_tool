#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import base64
import hashlib
import zlib
from urllib.parse import unquote
import binascii
from Crypto.Cipher import AES

# --- Key Generation ---

def gen_aes_key(key_str: str) -> bytes:
    """Generates the raw MD5 digest for AES."""
    return hashlib.md5(key_str.encode()).digest()

def gen_xor_key(key_str: str) -> bytes:
    """Generates the hex MD5 digest for XOR."""
    return hashlib.md5(key_str.encode()).hexdigest()[:16].encode()

# --- Decryption Implementations ---

def decrypt_aes_base64(payload_b64: str, key_str: str) -> str:
    """Decrypts a Godzilla V4 default AES_BASE64 payload."""
    if not payload_b64 or not key_str:
        return "[!] Payload or key is empty."
    try:
        password = gen_aes_key(key_str)
        raw_payload = base64.b64decode(payload_b64)
        iv = raw_payload[:16]
        encrypted_data = raw_payload[16:]
        cipher = AES.new(password, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        padding_length = decrypted_padded[-1]
        if padding_length > 16 or padding_length == 0:
            decrypted_data = decrypted_padded
        else:
            decrypted_data = decrypted_padded[:-padding_length]

        return decrypted_data.decode('utf-8', errors='ignore')
    except (binascii.Error, Exception) as e:
        return f"[!] AES_BASE64 Decryption failed: {e}"

def decrypt_xor_base64(payload_b64: str, key_str: str) -> str:
    """Decrypts a Godzilla V3 default XOR_BASE64 payload."""
    if not payload_b64 or not key_str:
        return "[!] Payload or key is empty."
    try:
        key_bytes = gen_xor_key(key_str)
        decoded_data = base64.b64decode(payload_b64)
        
        result = bytearray()
        for i in range(len(decoded_data)):
            result.append(decoded_data[i] ^ key_bytes[i % 16])
        decrypted_data = bytes(result)
        
        try:
            unzipped_data = zlib.decompress(decrypted_data, 16 + zlib.MAX_WBITS)
        except zlib.error:
            unzipped_data = decrypted_data

        return unzipped_data.decode('utf-8', errors='ignore')
    except (binascii.Error, Exception) as e:
        return f"[!] XOR_BASE64 Decryption failed: {e}"

# --- Dispatcher Function ---

def godzilla_decode(payload_str: str, key: str, crypter: str) -> str:
    """
    Dispatches to the correct Godzilla decrypter based on crypter type.
    For EVAL types, payload_str is the full request body.
    For others, it's the Base64 payload itself.
    """
    crypter_map = {
        'AES_BASE64 (V4 Default)': decrypt_aes_base64,
        'XOR_BASE64 (V3 Default)': decrypt_xor_base64
    }
    
    if crypter in crypter_map:
        return crypter_map[crypter](payload_str, key)
    
    elif crypter == 'PHP_EVAL_XOR_BASE64':
        try:
            # Payload is the full POST body: e.g., "pass=...&auth=..."
            # We need the value of the second parameter.
            actual_payload_b64 = payload_str.split('&', 1)[1].split('=', 1)[1]
            return decrypt_xor_base64(actual_payload_b64, key)
        except IndexError:
            return "[!] Invalid PHP_EVAL_XOR_BASE64 format. Expected 'param1=...&param2=...'."
    else:
        return f"[!] Unknown crypter specified: {crypter}"

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt a single Godzilla webshell payload.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Example:
  python3 decrypt_godzilla_payload.py <your_password> <base64_payload>
"""
    )
    parser.add_argument("payload", help="The payload string. For EVAL crypters, this is the full POST body.")
    parser.add_argument("-k", "--key", required=True, help="The connection password (key).")
    parser.add_argument(
        "-c", "--crypter", 
        required=True, 
        choices=['AES_BASE64 (V4 Default)', 'XOR_BASE64 (V3 Default)', 'PHP_EVAL_XOR_BASE64'], 
        help="Godzilla crypter type."
    )
    args = parser.parse_args()

    decrypted_text = godzilla_decode(args.payload, args.key, args.crypter)
    print("--- Decrypted Data ---")
    print(decrypted_text)

if __name__ == "__main__":
    main() 