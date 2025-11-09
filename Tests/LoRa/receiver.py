"""
Secure LoRa Receiver with UECDH + AES-CBC
Compatible with uecdh.py v3.0.0
"""

from machine import Pin, SPI
from time import sleep
from ulora.core import ULoRa
from uecdh import UECDH
import ucryptolib


# ==================== CONFIG ====================
LORA_PINS = {
    'dio_0': 33,
    'ss': 5,
    'reset': 32,
    'sck': 23,
    'miso': 19,
    'mosi': 18
}

# PKCS#7 Unpadding
def remove_pkcs7_padding(data, block_size=16):
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid PKCS#7 padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

# AES-CBC Decrypt
def aes_decrypt(encrypted, key):
    if len(encrypted) < 16:
        raise ValueError("Encrypted data too short")
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = ucryptolib.aes(key, 2, iv)  # CBC mode
    padded = cipher.decrypt(ciphertext)
    return remove_pkcs7_padding(padded)

# ==================== MAIN ====================
if __name__ == "__main__":
    try:
        print("Initializing SPI...")
        spi = SPI(1, baudrate=5000000, polarity=0, phase=0,
                  sck=Pin(LORA_PINS['sck']),
                  mosi=Pin(LORA_PINS['mosi']),
                  miso=Pin(LORA_PINS['miso']))

        pins = {
            "ss": LORA_PINS['ss'],
            "reset": LORA_PINS['reset'],
            "dio0": LORA_PINS['dio_0']
        }

        print("Initializing LoRa...")
        lora = ULoRa(spi, pins)

        print("Initializing UECDH (128-bit key)...")
        uecdh = UECDH()  # No key_size → always 32-byte, we truncate later
        priv_key, pub_key = uecdh.generate_keypair()
        aes_key = uecdh.compute_shared_key(length=16)  # 128-bit AES key
        print(f"Receiver public key: {pub_key.hex()}")

        # === Step 1: Receive Sender's Public Key ===
        print("\nListening for sender public key...")
        sender_pub = lora.listen(timeout=20000)
        if not sender_pub or len(sender_pub) != 32:
            raise RuntimeError("Invalid sender public key")
        print(f"Received sender pub: {sender_pub.hex()}")

        # === Step 2: Send Our Public Key ===
        print("Sending receiver public key...")
        sleep(1)
        lora.println(pub_key, binary=True)

        # === Step 3: Compute Shared AES Key ===
        uecdh.set_peer_public_key(sender_pub)
        aes_key = uecdh.compute_shared_key(length=16)  # 128-bit
        print(f"Derived AES key: {aes_key.hex()}")

        # === Step 4: Receive & Decrypt Message ===
        print("\nListening for encrypted message...")
        encrypted = lora.listen(timeout=20000)
        if encrypted and len(encrypted) > 16:
            try:
                plain = aes_decrypt(encrypted, aes_key)
                print(f"Decrypted: {plain.decode('utf-8', 'ignore')}")
            except Exception as e:
                print(f"Decryption failed: {e}")
        else:
            print("No valid message received.")

        # === Cleanup ===
        uecdh.clear()
        print("Session ended. Keys wiped.")

    except Exception as e:
        print(f"\nERROR: {e}")