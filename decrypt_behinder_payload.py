import base64
from Crypto.Cipher import AES
import hashlib
import binascii

# Behinder 3/4 dynamic key negotiation and decryption logic

def get_session_key(password: str) -> bytes:
    """
    Derives the initial session key from the webshell password.
    This key is used only for the first handshake.
    For default Behinder 3 shells, this is md5(password)[:16].
    """
    return hashlib.md5(password.encode()).digest()[:16]

def decrypt_first_response(response_data: bytes, session_key: bytes) -> bytes:
    """
    Decrypts the first HTTP response from the server to get the dynamic crypto key.
    Behinder uses AES/ECB for this handshake.
    """
    try:
        cipher = AES.new(session_key, AES.MODE_ECB)
        decrypted_key = cipher.decrypt(response_data)
        # The real dynamic key is often padded or has extra bytes
        return decrypted_key[:16]
    except Exception:
        # If decryption fails, it might not be a valid Behinder response
        return b''

def decrypt_subsequent_payload(payload_data: bytes, dynamic_key: bytes) -> str:
    """
    Decrypts subsequent requests or responses using the dynamic key.
    Behinder uses AES/CBC for regular communication.
    The IV is the MD5 hash of the dynamic key.
    """
    try:
        iv = hashlib.md5(dynamic_key).digest()
        cipher = AES.new(dynamic_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(payload_data)
        
        # PKCS7 Unpadding
        padding_len = decrypted_padded[-1]
        if padding_len > 16 or padding_len == 0:
            # Invalid padding, return as is
            decrypted_data = decrypted_padded
        else:
            # Check if padding is valid
            if decrypted_padded[-padding_len:] != bytes([padding_len]) * padding_len:
                decrypted_data = decrypted_padded # Invalid padding
            else:
                decrypted_data = decrypted_padded[:-padding_len]

        # The result might be Java-serialized objects, but we'll return the string representation
        return decrypted_data.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[!] Payload decryption failed: {e}"

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Decrypt a single Behinder payload. This requires the DYNAMIC session key.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("payload", help="The raw encrypted payload (should be Base64 decoded first).")
    parser.add_argument("-k", "--key", required=True, help="The DYNAMIC key for the session (16 bytes, extracted from handshake).")
    
    args = parser.parse_args()

    # This tool is for decrypting subsequent payloads, not the initial handshake
    # The user must provide the dynamic key sniffed from the traffic.
    try:
        raw_payload = base64.b64decode(args.payload)
        dynamic_key_bytes = base64.b64decode(args.key)
        
        if len(dynamic_key_bytes) != 16:
            print("[!] Error: Dynamic key must be 16 bytes long.")
            return

        decrypted_text = decrypt_subsequent_payload(raw_payload, dynamic_key_bytes)
        print("--- Decrypted Data ---")
        print(decrypted_text)
    except binascii.Error:
        print("[!] Error: Payload or key is not valid Base64.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")


if __name__ == "__main__":
    main() 