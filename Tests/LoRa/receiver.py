from machine import Pin, SPI
from time import sleep
from ulora.core import ULoRa
from uecdh.uecdh import UECDH
import ucryptolib



# Pin Configuration
LORA_PINS = {
    'dio_0': 33,
    'ss': 5,
    'reset': 32,
    'sck': 23,
    'miso': 19,
    'mosi': 18
}

# PKCS#7 Unpadding Function
def remove_pkcs7_padding(data, block_size=16):
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padding")
    padding_len = data[-1]
    if padding_len > block_size or padding_len == 0:
        raise ValueError("Invalid padding length")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding bytes")
    return data[:-padding_len]

# AES Decryption Function
def aes_decrypt(data, key):
    iv = data[:16]  # Extract 16-byte IV
    ciphertext = data[16:]  # Extract ciphertext
    cipher = ucryptolib.aes(key, 2, iv)  # Mode 2 is CBC in ucryptolib
    decrypted = cipher.decrypt(ciphertext)
    return remove_pkcs7_padding(decrypted)  # Remove PKCS#7 padding

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
        lora = ULoRa(spi, pins)
        print("ULoRa instance created successfully.")

        # Initialize UECDH
        print("Initializing UECDH for key exchange...")
        uecdh = UECDH(key_size=16)  # 128-bit key for AES
        private_key, public_key = uecdh.generate_keypair()
        print(f"Receiver public key: {public_key.hex()}")

        # Receive Sender's Public Key
        print("\n----- Listening for Sender's Public Key -----")
        sender_public_key = lora.listen(timeout=20000)  # 20 seconds timeout
        if not sender_public_key:
            raise RuntimeError("Failed to receive sender's public key")
        print(f"Received sender's public key: {sender_public_key.hex()}")

        # Send Receiver's Public Key
        print("Sending receiver's public key...")
        sleep(2)  # Wait for sender to process
        lora.println(public_key)

        # Compute Shared Key
        shared_key = uecdh.compute_shared_key(sender_public_key)
        print(f"Shared key: {shared_key.hex()}")

        # Receive and Decrypt Message
        print("\n----- Listening for Encrypted Message -----")
        encrypted_message = lora.listen(timeout=20000)
        if encrypted_message:
            print(f"Received encrypted message: {encrypted_message.hex()}")
            decrypted_message = aes_decrypt(encrypted_message, shared_key)
            print(f"Decrypted message: {decrypted_message.decode()}")
        else:
            print("No message received within the timeout period.")

        # Clear Keys
        uecdh.clear_keys()

    except Exception as e:
        print("\nError during test:")
        print(f"Exception: {e}")
        print("Please check the wiring, LoRa module configuration, or UECDH errors.")
