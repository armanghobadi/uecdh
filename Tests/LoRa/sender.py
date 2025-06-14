from machine import Pin, SPI
from time import sleep
from ulora.core import ULoRa
from uecdh.uecdh import UECDH
import ucryptolib
import urandom

# LoRa Configuration
LORA_CONFIG = {
    'frequency': 433000000,
    'frequency_offset': 0,
    'tx_power_level': 20,
    'signal_bandwidth': 125e3,
    'spreading_factor': 7,
    'coding_rate': 5,
    'preamble_length': 8,
    'implicitHeader': True,
    'sync_word': 0x2e,
    'enable_CRC': True,
    'invert_IQ': True,
    'debug': False
}

# Pin Configuration
LORA_PINS = {
    'dio_0': 13,
    'ss': 14,
    'reset': 35,
    'sck': 25,
    'miso': 26,
    'mosi': 27
}

# PKCS#7 Padding Function
def add_pkcs7_padding(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len]) * padding_len
    return data + padding

# AES Encryption Function
def aes_encrypt(data, key):
    iv = urandom.getrandbits(128).to_bytes(16, 'big')  # 16-byte IV for CBC
    padded_data = add_pkcs7_padding(data)  # Add PKCS#7 padding
    cipher = ucryptolib.aes(key, 2, iv)  # Mode 2 is CBC in ucryptolib
    encrypted = cipher.encrypt(padded_data)
    return iv + encrypted  # Prepend IV to encrypted data

# Main Program
if __name__ == "__main__":
    try:
        # Initialize SPI
        print("Initializing SPI bus...")
        spi = SPI(1, baudrate=5000000, polarity=0, phase=0,
                  sck=Pin(LORA_PINS['sck']), mosi=Pin(LORA_PINS['mosi']), miso=Pin(LORA_PINS['miso']))
        print(f"SPI bus initialized with SCK: {LORA_PINS['sck']}, MOSI: {LORA_PINS['mosi']}, MISO: {LORA_PINS['miso']}.")

        # Define Pin Mappings
        print("Setting up pin configurations...")
        pins = {
            "ss": LORA_PINS['ss'],
            "reset": LORA_PINS['reset'],
            "dio0": LORA_PINS['dio_0']
        }
        print(f"Pin configuration: SS={pins['ss']}, Reset={pins['reset']}, DIO0={pins['dio0']}.")

        # Create ULoRa Instance
        print("Creating ULoRa instance...")
        lora = ULoRa(spi, pins, **LORA_CONFIG)
        print("ULoRa instance created successfully.")

        # Initialize UECDH
        print("Initializing UECDH for key exchange...")
        uecdh = UECDH(key_size=16)  # 128-bit key for AES
        private_key, public_key = uecdh.generate_keypair()
        print(f"Sender public key: {public_key.hex()}")

        # Send Public Key
        print("Sending public key...")
        lora.println(public_key, binary=True)  # Send as binary
        sleep(1)  # Wait for receiver to process

        # Receive Receiver's Public Key
        print("Waiting for receiver's public key...")
        their_public_key = lora.listen(timeout=20000)  # 20 seconds timeout
        if not their_public_key:
            raise RuntimeError("Failed to receive receiver's public key")
        print(f"Received receiver's public key: {their_public_key.hex()}")

        # Compute Shared Key
        shared_key = uecdh.compute_shared_key(their_public_key)
        print(f"Shared key: {shared_key.hex()}")

        # Encrypt and Send Test Message
        test_message = "Hello From Arman Ghobadi"
        print(f"\n----- Transmitting Encrypted Message -----")
        print(f"Original message: {test_message}")
        encrypted_message = aes_encrypt(test_message.encode(), shared_key)
        print(f"Encrypted message: {encrypted_message.hex()}")
        lora.println(encrypted_message, binary=True)
        print("Message transmission complete.")

        # Clear Keys
        uecdh.clear_keys()

    except Exception as e:
        print("\nError during test:")
        print(f"Exception: {e}")
        print("Please check the wiring, LoRa module configuration, or UECDH errors.")