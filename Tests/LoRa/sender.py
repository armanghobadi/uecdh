"""
Secure LoRa Sender with UECDH + AES-CBC
Compatible with uecdh.py v3.0.0
"""

from machine import Pin, SPI
from time import sleep
from ulora.core import ULoRa
from uecdh import UECDH
import ucryptolib
import urandom


# ==================== CONFIG ====================
LORA_CONFIG = {
    'frequency': 433000000,
    'tx_power_level': 20,
    'signal_bandwidth': 125e3,
    'spreading_factor': 7,
    'coding_rate': 5,
    'preamble_length': 8,
    'implicitHeader': True,
    'sync_word': 0x2e,
    'enable_CRC': True,
    'invert_IQ': True,
}

LORA_PINS = {
    'dio_0': 13,
    'ss': 14,
    'reset': 35,
    'sck': 25,
    'miso': 26,
    'mosi': 27
}

# PKCS#7 Padding
def add_pkcs7_padding(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

# AES-CBC Encrypt
def aes_encrypt(plain, key):
    iv = bytearray(16)
    for i in range(16):
        iv[i] = urandom.getrandbits(8)
    iv = bytes(iv)
    padded = add_pkcs7_padding(plain)
    cipher = ucryptolib.aes(key, 2, iv)
    encrypted = cipher.encrypt(padded)
    return iv + encrypted

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
        lora = ULoRa(spi, pins, **LORA_CONFIG)

        print("Initializing UECDH...")
        uecdh = UECDH()
        priv_key, pub_key = uecdh.generate_keypair()
        print(f"Sender public key: {pub_key.hex()}")

        # === Step 1: Send Public Key ===
        print("\nSending public key...")
        lora.println(pub_key, binary=True)
        sleep(1)

        # === Step 2: Receive Receiver's Public Key ===
        print("Waiting for receiver public key...")
        receiver_pub = lora.listen(timeout=20000)
        if not receiver_pub or len(receiver_pub) != 32:
            raise RuntimeError("Invalid receiver public key")
        print(f"Received receiver pub: {receiver_pub.hex()}")

        # === Step 3: Compute Shared AES Key ===
        uecdh.set_peer_public_key(receiver_pub)
        aes_key = uecdh.compute_shared_key(length=16)  # 128-bit
        print(f"Derived AES key: {aes_key.hex()}")

        # === Step 4: Encrypt & Send Message ===
        message = "Hello From Arman Ghobadi"
        print(f"\nEncrypting: {message}")
        encrypted = aes_encrypt(message.encode(), aes_key)
        print(f"Encrypted: {encrypted.hex()}")
        lora.println(encrypted, binary=True)
        print("Message sent.")

        # === Cleanup ===
        uecdh.clear()
        print("Session ended. Keys wiped.")

    except Exception as e:
        print(f"\nERROR: {e}")