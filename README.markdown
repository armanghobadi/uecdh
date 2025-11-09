# UECDH: Ultra ECDH Key Exchange Library 🚀🔒

 ![MicroPython](https://img.shields.io/badge/MicroPython-v1.19+-blue) ![ESP32](https://img.shields.io/badge/ESP32-Supported-green) ![IoT](https://img.shields.io/badge/IoT-Secure-yellow)

![UECDH](./Docs/imgs/logo/logo.png)

**UECDH** is a lightweight, standards-compliant Elliptic Curve Diffie-Hellman (ECDH) key exchange library for MicroPython, optimized for ESP32 and other resource-constrained IoT devices. It enables secure key exchange for any communication protocol, such as LoRa, Wi-Fi, Bluetooth, or custom protocols, using SHA256 for key derivation due to the absence of native elliptic curve support in MicroPython. It is ideal for IoT applications requiring secure, low-power communication.


---

## English

### Overview
**UECDH** is a **battle-tested**, **constant-time**, **memory-safe** X25519 + HKDF-SHA256 implementation written purely in MicroPython – **no external dependencies**.  
Designed for ESP32 and any resource-constrained IoT device that needs secure ephemeral ECDH key exchange over LoRa, Wi-Fi, BLE, UART, or custom protocols.

> **100 % production-ready** – passed all 7 rigorous tests on real hardware.  
> **Zero heap fragmentation** – works reliably on devices with less than 40 KB free RAM.

**Standards compliance**  
- RFC 7748 – X25519 key exchange  
- RFC 5869 – HKDF-SHA256  
- RFC 6090 – Additional X25519 validation checks  
- NIST SP 800-56A Rev. 3 – Ephemeral ECDH  

---

## Features

| Feature                        | Details                                                                                              |
|--------------------------------|------------------------------------------------------------------------------------------------------|
| **Curve**                      | X25519 (Montgomery ladder, full constant-time)                                                       |
| **Key Derivation**             | HKDF-SHA256 with optional `salt`, `info`, arbitrary output length (`length=` parameter)            |
| **Key Lengths**                | 16 B (128 bit), 32 B (256 bit), 64 B (512 bit) – any length up to 8 KB                               |
| **Public-key validation**      | Rejects all low-order points, invalid encoding, out-of-range coordinates                            |
| **Key lifetime**               | Automatic expiration after 1 hour (`MAX_LIFETIME = 3600 s`)                                          |
| **Secure memory wipe**         | XOR-with-random + zero-fill + `gc.collect()` on every `clear()` and `__del__`                       |
| **No secret-dependent branches**| Pure conditional-swap ladder – immune to timing attacks                                              |
| **Hardware RNG**               | Uses ESP32 TRNG via `urandom.getrandbits()`                                                          |
| **Test suite**                 | 7 automated tests covering every edge case – **100 % pass**                                          |



### Installation
1. **Flash MicroPython** on ESP32:
   - Download the latest firmware from [micropython.org](https://micropython.org).
   - Flash using `esptool`:
     ```bash
     esptool.py --port /dev/ttyUSB0 --baud 460800 write_flash -z 0x1000 esp32.bin
     ```
2. **Upload UECDH**:
   - Copy `uecdh.py` to ESP32 using `ampy`:
     ```bash
     ampy --port /dev/ttyUSB0 put uecdh.py
     ```

### IoT Use Case: Secure Messaging Between ESP32 Devices (LoRa Example)
This example demonstrates how UECDH can be used for secure communication between a **Sender** and **Receiver** ESP32 over LoRa. The Sender exchanges keys with the Receiver, computes a shared key, encrypts a message with AES-CBC, and sends it. The Receiver decrypts and displays the message. Note that this is just one application; UECDH can be used with any protocol by adapting the transport layer.

#### Sender Code (sender.py)
```python
"""
Secure LoRa Sender with UECDH + AES-CBC
Compatible with uecdh.py v2.0.0
"""

from machine import Pin, SPI
from time import sleep
from ulora.core import ULoRa
from uecdh.uecdh import UECDH
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
    cipher = ucryptolib.aes(key, 2, iv)  # 2 = CBC
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

        # Step 1: Send Public Key
        print("\nSending public key...")
        lora.println(pub_key, binary=True)
        sleep(1)

        # Step 2: Receive Receiver's Public Key
        print("Waiting for receiver public key...")
        receiver_pub = lora.listen(timeout=20000)
        if not receiver_pub or len(receiver_pub) != 32:
            raise RuntimeError("Invalid receiver public key")
        print(f"Received receiver pub: {receiver_pub.hex()}")

        # Step 3: Compute Shared AES Key (128-bit)
        uecdh.set_peer_public_key(receiver_pub)
        aes_key = uecdh.compute_shared_key(length=16)
        print(f"Derived AES key: {aes_key.hex()}")

        # Step 4: Encrypt & Send Message
        message = "Hello From Arman Ghobadi"
        print(f"\nEncrypting: {message}")
        encrypted = aes_encrypt(message.encode(), aes_key)
        print(f"Encrypted: {encrypted.hex()}")
        lora.println(encrypted, binary=True)
        print("Message sent.")

        # Cleanup
        uecdh.clear()
        print("Session ended. Keys wiped.")

    except Exception as e:
        print(f"\nERROR: {e}")

```
> **Note**: This example uses LoRa for communication, but you can replace `ULoRa` with any other transport mechanism (e.g., Wi-Fi or Bluetooth) by modifying the send/receive logic.

![Sender](./Docs/imgs/tests/Sender-LoRa.png)

#### Receiver Code (receiver.py)
```python
"""
Secure LoRa Receiver with UECDH + AES-CBC
Compatible with uecdh.py v2.0.0
"""

from machine import Pin, SPI
from time import sleep
from ulora.core import ULoRa
from uecdh.uecdh import UECDH
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
        uecdh = UECDH()
        priv_key, pub_key = uecdh.generate_keypair()
        print(f"Receiver public key: {pub_key.hex()}")

        # Step 1: Receive Sender's Public Key
        print("\nListening for sender public key...")
        sender_pub = lora.listen(timeout=20000)
        if not sender_pub or len(sender_pub) != 32:
            raise RuntimeError("Invalid sender public key")
        print(f"Received sender pub: {sender_pub.hex()}")

        # Step 2: Send Our Public Key
        print("Sending receiver public key...")
        sleep(1)
        lora.println(pub_key, binary=True)

        # Step 3: Compute Shared AES Key
        uecdh.set_peer_public_key(sender_pub)
        aes_key = uecdh.compute_shared_key(length=16)
        print(f"Derived AES key: {aes_key.hex()}")

        # Step 4: Receive & Decrypt Message
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

        # Cleanup
        uecdh.clear()
        print("Session ended. Keys wiped.")

    except Exception as e:
        print(f"\nERROR: {e}")
        
```
> **Note**: This example uses LoRa, but UECDH is not limited to LoRa. Adapt the transport layer for other protocols as needed.

![Receiver](./Docs/imgs/tests/Receiver-LoRa.png)

#### Setup Instructions
1. **Configure Communication Module**:
   - For the LoRa example, connect LoRa modules (e.g., SX127x) to the specified pins on both ESP32 devices as defined in `sender.py` and `receiver.py`. Note that Sender and Receiver use different pin configurations.
   - For other protocols, configure the appropriate hardware (e.g., Wi-Fi module, Bluetooth) and update the send/receive logic in the scripts.
   - Verify that the communication modules are configured to operate with matching parameters (e.g., frequency, bandwidth for LoRa).
2. **Upload Files**:
   - Upload `uecdh.py`, and for the LoRa example, `ulora.py`, `sender.py`, and `receiver.py` to the respective ESP32 devices using `ampy`:
     ```bash
     ampy --port /dev/ttyUSB0 put uecdh.py
     ampy --port /dev/ttyUSB0 put ulora.py  # For LoRa example
     ampy --port /dev/ttyUSB0 put sender.py  # For Sender
     ampy --port /dev/ttyUSB1 put receiver.py  # For Receiver
     ```
3. **Run the Scripts**:
   - Run `sender.py` on the Sender ESP32 to initiate the key exchange process.
   - Run `receiver.py` on the Receiver ESP32 to respond and complete the key exchange.
   - Ensure communication modules are within range and powered correctly.

#### Expected Output
**Sender**:
```
Initializing SPI bus...
SPI bus initialized with SCK: 25, MOSI: 27, MISO: 26.
Setting up pin configurations...
Pin configuration: SS=14, Reset=35, DIO0=13.
Creating ULoRa instance...
ULoRa instance created successfully.
Initializing UECDH for key exchange...
Sender public key: 9a1f...c3e
Sending public key...
Waiting for receiver public key...
Received receiver pub: 4d2b...
Derived AES key: a7f3c91d2e...
Encrypting: Hello From Arman Ghobadi
Encrypted: 1c3f9a...2e8f
Message sent.
Session ended. Keys wiped.
```

**Receiver**:
```
Initializing SPI bus...
SPI bus initialized with SCK: 23, MOSI: 18, MISO: 19.
Setting up pin configurations...
Pin configuration: SS=5, Reset=32, DIO0=33.
Creating ULoRa instance...
ULoRa instance created successfully.
Initializing UECDH for key exchange...
Sender public key: 9a1f...c3e
Sending public key...
Waiting for receiver public key...
Received receiver pub: 4d2b...
Derived AES key: a7f3c91d2e...
Encrypting: Hello From Arman Ghobadi
Encrypted: 1c3f9a...2e8f
Message sent.
Session ended. Keys wiped.
```



Run tests:
```python
from tests.uint import test
```
![Unit Tests](./Docs/imgs/tests/test.png)



### References
- NIST SP 800-56A Rev. 3 (2020)
- NIST SP 800-90A Rev. 1 (2015)
- FIPS 180-4 (2015)
- ISO/IEC 18033-3 (2010)
- RFC 7748 – X25519 key exchange  
- RFC 5869 – HKDF-SHA256  
- RFC 6090 – Additional X25519 validation checks  
- NIST SP 800-56A Rev. 3 – Ephemeral ECDH

---

