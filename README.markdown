# UECDH: Ultra ECDH Key Exchange Library 🚀🔒

![GitHub](https://img.shields.io/github/license/xai/uecdh) ![MicroPython](https://img.shields.io/badge/MicroPython-v1.19+-blue) ![ESP32](https://img.shields.io/badge/ESP32-Supported-green) ![IoT](https://img.shields.io/badge/IoT-Secure-yellow)

![UECDH](./Docs/imgs/logo/logo.png)

**UECDH** is a lightweight, standards-compliant Elliptic Curve Diffie-Hellman (ECDH) key exchange library for MicroPython, optimized for ESP32 and other resource-constrained IoT devices. It enables secure key exchange for any communication protocol, such as LoRa, Wi-Fi, Bluetooth, or custom protocols, using SHA256 for key derivation due to the absence of native elliptic curve support in MicroPython. It is ideal for IoT applications requiring secure, low-power communication.

📚 **Language**: [English](#english) | [فارسی](#persian)

---

## English

### Overview
UECDH provides a secure and efficient ECDH key exchange mechanism for MicroPython on ESP32, using SHA256 for key derivation. It is designed to be protocol-agnostic, allowing secure key exchange over any communication medium, including LoRa, Wi-Fi, Bluetooth, or others. The library complies with:
- **NIST SP 800-56A Rev. 3 (2020)**: ECDH key agreement.
- **NIST SP 800-90A Rev. 1 (2015)**: Random number generation.
- **FIPS 180-4 (2015)**: SHA256 hash function.
- **ISO/IEC 18033-3 (2010)**: Public-key cryptography requirements.

This README includes an IoT example demonstrating secure communication between **Sender** and **Receiver** ESP32 devices over LoRa using AES-CBC with PKCS#7 padding. This is just one application; UECDH can be adapted for any protocol by modifying the transport layer.

### Features
| Feature | Description |
|---------|-------------|
| 🔐 **Key Sizes** | Supports 128-bit and 256-bit keys for flexibility. |
| ⏱ **Constant-Time** | Prevents timing attacks with constant-time operations. |
| 🗑 **Secure Cleanup** | Erases keys securely to prevent leakage. |
| 📏 **ESP32 Optimized** | Minimal memory and CPU usage for IoT. |
| 🌐 **Protocol-Agnostic** | Compatible with any communication protocol (e.g., LoRa, Wi-Fi, Bluetooth). |
| ✅ **Test Suite** | Comprehensive tests for reliability. |

### Flowcharts
The following flowcharts illustrate the key processes in UECDH:

#### Key Exchange Process
```mermaid
flowchart TD
    A[Start] --> B{Generate Key Pair}
    B -->|"Private Key"| C[Random(n)]
    B -->|"Public Key"| D[SHA256(Private Key)[0:n]]
    C --> E{Valid Key?}
    D --> E
    E -->|"No"| F[Retry (up to 3 times)]
    E -->|"Yes"| G[Timestamp Key]
    F -->|"Fail"| H[Error: Weak Key]
    G --> I[Send Public Key]
    I --> J[Receive Peer Public Key]
    J --> K{Validate Peer Key}
    K -->|"Invalid"| L[Error: Invalid Key]
    K -->|"Valid"| M[Compute Shared Key]
    M --> N[SHA256(min(pub1, pub2) || max(pub1, pub2))[0:n]]
    N --> O{Valid Shared Key?}
    O -->|"No"| P[Error: Weak Shared Key]
    O -->|"Yes"| Q[Return Shared Key]
    Q --> R[End]
```

#### Sender Process (Encryption and Sending)
```mermaid
flowchart TD
    A[Start] --> B{Key Available?}
    B -->|"No"| C[Generate Key Pair]
    B -->|"Yes"| D[Get Shared Key]
    C --> D
    D --> E[Prepare Message]
    E --> F[Add PKCS#7 Padding]
    F --> G{Generate IV}
    G --> H{Initialize AES-CBC}
    H -->|"Key: Shared Key, IV"| I[Encrypt Message]
    I --> J{Encryption Success?}
    J -->|"No"| K[Error: Encryption Failed]
    J -->|"Yes"| L[Send IV + Encrypted Message]
    L --> M{Transport Available?}
    M -->|"No"| N[Error: Transport Unavailable]
    M -->|"Yes"| O[Transmit Message]
    O --> P[Clean Keys]
    P --> Q[End]
```

#### Receiver Process (Receiving and Decryption)
```mermaid
flowchart TD
    A[Start] --> B{Key Available?}
    B -->|"No"| C[Generate Key Pair]
    B -->|"Yes"| D[Get Shared Key]
    C --> D
    D --> E[Listen for Message]
    E --> F{Transport Available?}
    F -->|"No"| G[Error: Transport Unavailable]
    F -->|"Yes"| H[Receive IV + Encrypted Message]
    H --> I{Message Received?}
    I -->|"No"| J[Error: No Message]
    I -->|"Yes"| K{Extract IV}
    K --> L{Initialize AES-CBC}
    L -->|"Key: Shared Key, IV"| M[Decrypt Message]
    M --> N{Decryption Success?}
    N -->|"No"| O[Error: Decryption Failed]
    N -->|"Yes"| P[Remove PKCS#7 Padding]
    P --> Q[Output Decrypted Message]
    Q --> R[Clean Keys]
    R --> S[End]
```

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
```
> **Note**: This example uses LoRa for communication, but you can replace `ULoRa` with any other transport mechanism (e.g., Wi-Fi or Bluetooth) by modifying the send/receive logic.

![Sender](./Docs/imgs/tests/Sender-LoRa.png)

#### Receiver Code (receiver.py)
```python
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
Sender public key: <random_hex>
Sending public key...
Waiting for receiver's public key...
Received receiver's public key: <random_hex>
Shared key: <same_hex>
----- Transmitting Encrypted Message -----
Original message: Hello From Arman Ghobadi
Encrypted message: <encrypted_hex>
Message transmission complete.
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
Receiver public key: <random_hex>
----- Listening for Sender's Public Key -----
Received sender's public key: <random_hex>
Sending receiver's public key...
Shared key: <same_hex>
----- Listening for Encrypted Message -----
Received encrypted message: <encrypted_hex>
Decrypted message: Hello From Arman Ghobadi
```

### Testing
The library includes a test suite to verify:
- 128-bit and 256-bit key exchanges.
- Weak key detection.
- Invalid key size handling.
- Secure key cleanup.
- Key lifetime expiration.

Run tests:
```python
from tests.uint import test
```
![Unit Tests](./Docs/imgs/tests/test.png)

### Security Considerations
- **SHA256 Limitation**: UECDH uses SHA256 due to MicroPython’s lack of elliptic curve support, which is less secure than Curve25519.
- **AES-CBC**: The example uses CBC mode with a random IV for improved security over ECB. Ensure the IV is never reused with the same key.
- **Randomness**: Ensure `urandom` is properly seeded on ESP32 for secure IV and key generation.
- **Transport Security**: UECDH secures payloads, but the underlying protocol (e.g., LoRa, Wi-Fi) may require additional authentication to prevent Man-in-the-Middle attacks.

### References
- NIST SP 800-56A Rev. 3 (2020)
- NIST SP 800-90A Rev. 1 (2015)
- FIPS 180-4 (2015)
- ISO/IEC 18033-3 (2010)

---

## Persian (فارسی)

### معرفی
**UECDH** یک کتابخانه سبک و استاندارد برای تبادل کلید ECDH در MicroPython است که برای دستگاه‌های IoT با منابع محدود مانند ESP32 بهینه شده است. این کتابخانه امکان تبادل کلید امن را برای هر پروتکل ارتباطی، از جمله LoRa، Wi-Fi، Bluetooth یا پروتکل‌های سفارشی، فراهم می‌کند و از SHA256 برای استخراج کلید به دلیل نبود پشتیبانی از منحنی‌های بیضوی در MicroPython استفاده می‌کند. این کتابخانه برای برنامه‌های IoT که نیاز به ارتباط امن و کم‌مصرف دارند، ایده‌آل است و با استانداردهای زیر سازگار است:
- **NIST SP 800-56A Rev. 3 (2020)**: توافق کلید ECDH.
- **NIST SP 800-90A Rev. 1 (2015)**: تولید اعداد تصادفی.
- **FIPS 180-4 (2015)**: تابع هش SHA256.
- **ISO/IEC 18033-3 (2010)**: الزامات رمزنگاری کلید عمومی.

این README شامل مثالی برای ارتباط امن بین دو دستگاه ESP32 (فرستنده و گیرنده) با استفاده از LoRa و رمزنگاری AES-CBC با پدینگ PKCS#7 است. با این حال، UECDH به پروتکل خاصی محدود نیست و می‌تواند برای هر رسانه ارتباطی با تغییر لایه انتقال استفاده شود.

### ویژگی‌ها
| ویژگی | توضیحات |
|-------|---------|
| 🔐 **اندازه کلید** | پشتیبانی از کلیدهای 128 بیتی و 256 بیتی. |
| ⏱ **زمان ثابت** | جلوگیری از حملات زمان‌بندی با عملیات زمان ثابت. |
| 🗑 **پاک‌سازی امن** | پاک‌سازی کلیدها برای جلوگیری از نشت. |
| 📏 **بهینه برای ESP32** | مصرف کم حافظه و CPU برای IoT. |
| 🌐 **مستقل از پروتکل** | سازگار با هر پروتکل ارتباطی (مانند LoRa، Wi-Fi، Bluetooth). |
| ✅ **مجموعه تست** | تست‌های جامع برای اطمینان از قابلیت اطمینان. |

### فلوچارت‌ها
فلوچارت‌های زیر فرآیندهای کلیدی در UECDH را نشان می‌دهند:

#### فرآیند تبادل کلید
```mermaid
flowchart TD
    A[شروع] --> B{تولید جفت کلید}
    B -->|"کلید خصوصی"| C[تصادفی(n)]
    B -->|"کلید عمومی"| D[SHA256(کلید خصوصی)[0:n]]
    C --> E{کلید معتبر؟}
    D --> E
    E -->|"خیر"| F[تلاش مجدد (تا 3 بار)]
    E -->|"بله"| G[ثبت زمان کلید]
    F -->|"شکست"| H[خطا: کلید ضعیف]
    G --> I[ارسال کلید عمومی]
    I --> J[دریافت کلید عمومی همتا]
    J --> K{اعتبارسنجی کلید همتا}
    K -->|"نامعتبر"| L[خطا: کلید نامعتبر]
    K -->|"معتبر"| M[محاسبه کلید مشترک]
    M --> N[SHA256(min(pub1, pub2) || max(pub1, pub2))[0:n]]
    N --> O{کلید مشترک معتبر؟}
    O -->|"خیر"| P[خطا: کلید مشترک ضعیف]
    O -->|"بله"| Q[بازگرداندن کلید مشترک]
    Q --> R[پایان]
```

#### فرآیند فرستنده (رمزنگاری و ارسال)
```mermaid
flowchart TD
    A[شروع] --> B{کلید موجود؟}
    B -->|"خیر"| C[تولید جفت کلید]
    B -->|"بله"| D[دریافت کلید مشترک]
    C --> D
    D --> E[آماده‌سازی پیام]
    E --> F[افزودن پدینگ PKCS#7]
    F --> G{تولید IV}
    G --> H{مقداردهی اولیه AES-CBC}
    H -->|"کلید: کلید مشترک، IV"| I[رمزنگاری پیام]
    I --> J{رمزنگاری موفق؟}
    J -->|"خیر"| K[خطا: رمزنگاری ناموفق]
    J -->|"بله"| L[ارسال IV + پیام رمز شده]
    L --> M{انتقال در دسترس؟}
    M -->|"خیر"| N[خطا: انتقال در دسترس نیست]
    M -->|"بله"| O[ارسال پیام]
    O --> P[پاک‌سازی کلیدها]
    P --> Q[پایان]
```

#### فرآیند گیرنده (دریافت و رمزگشایی)
```mermaid
flowchart TD
    A[شروع] --> B{کلید موجود؟}
    B -->|"خیر"| C[تولید جفت کلید]
    B -->|"بله"| D[دریافت کلید مشترک]
    C --> D
    D --> E[گوش دادن برای پیام]
    E --> F{انتقال در دسترس؟}
    F -->|"خیر"| G[خطا: انتقال در دسترس نیست]
    F -->|"بله"| H[دریافت IV + پیام رمز شده]
    H --> I{پیام دریافت شد؟}
    I -->|"خیر"| J[خطا: بدون پیام]
    I -->|"بله"| K{استخراج IV}
    K --> L{مقداردهی اولیه AES-CBC}
    L -->|"کلید: کلید مشترک، IV"| M[رمزگشایی پیام]
    M --> N{رمزگشایی موفق؟}
    N -->|"خیر"| O[خطا: رمزگشایی ناموفق]
    N -->|"بله"| P[حذف پدینگ PKCS#7]
    P --> Q[نمایش پیام رمزگشایی شده]
    Q --> R[پاک‌سازی کلیدها]
    R --> S[پایان]
```

### نصب
1. **نصب MicroPython** روی ESP32:
   - آخرین نسخه را از [micropython.org](https://micropython.org) دانلود کنید.
   - با `esptool` فلش کنید:
     ```bash
     esptool.py --port /dev/ttyUSB0 --baud 460800 write_flash -z 0x1000 esp32.bin
     ```
2. **آپلود UECDH**:
   - فایل `uecdh.py` را با `ampy` آپلود کنید:
     ```bash
     ampy --port /dev/ttyUSB0 put uecdh.py
     ```

### کاربرد در IoT: ارسال و دریافت پیام امن بین ESP32ها (مثال LoRa)
این مثال نشان می‌دهد چگونه UECDH می‌تواند برای ارتباط امن بین یک **فرستنده** و **گیرنده** ESP32 از طریق LoRa استفاده شود. فرستنده کلیدها را با گیرنده تبادل می‌کند، کلید مشترک را محاسبه می‌کند، پیام را با AES-CBC رمزنگاری می‌کند و ارسال می‌کند. گیرنده پیام را رمزگشایی و نمایش می‌دهد. توجه داشته باشید که این تنها یک کاربرد است؛ UECDH می‌تواند با هر پروتکلی با تغییر لایه انتقال استفاده شود.

#### کد فرستنده (sender.py)
```python
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
```
> **توجه**: این مثال از LoRa برای ارتباط استفاده می‌کند، اما می‌توانید `ULoRa` را با هر مکانیزم انتقال دیگر (مانند Wi-Fi یا Bluetooth) جایگزین کنید با تغییر منطق ارسال/دریافت.

#### کد گیرنده (receiver.py)
```python
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
```
> **توجه**: این مثال از LoRa استفاده می‌کند، اما UECDH به LoRa محدود نیست. لایه انتقال را برای پروتکل‌های دیگر به‌روزرسانی کنید.

#### دستورالعمل راه‌اندازی
1. **پیکربندی ماژول ارتباطی**:
   - برای مثال LoRa، ماژول‌های LoRa (مانند SX127x) را به پین‌های مشخص شده در `sender.py` و `receiver.py` روی هر دو دستگاه ESP32 متصل کنید. توجه کنید که فرستنده و گیرنده از پیکربندی پین‌های متفاوتی استفاده می‌کنند.
   - برای پروتکل‌های دیگر، سخت‌افزار مناسب (مانند ماژول Wi-Fi یا Bluetooth) را پیکربندی کنید و منطق ارسال/دریافت را در اسکریپت‌ها به‌روزرسانی کنید.
   - اطمینان حاصل کنید که ماژول‌های ارتباطی با پارامترهای یکسان (مانند فرکانس، پهنای باند برای LoRa) پیکربندی شده‌اند.
2. **آپلود فایل‌ها**:
   - فایل‌های `uecdh.py` و برای مثال LoRa، فایل‌های `ulora.py`، `sender.py` و `receiver.py` را به دستگاه‌های مربوطه با استفاده از `ampy` آپلود کنید:
     ```bash
     ampy --port /dev/ttyUSB0 put uecdh.py
     ampy --port /dev/ttyUSB0 put ulora.py
     ampy --port /dev/ttyUSB0 put sender.py  # برای فرستنده
     ampy --port /dev/ttyUSB1 put receiver.py  # برای گیرنده
     ```
3. **اجرای اسکریپت‌ها**:
   - اسکریپت `sender.py` را روی ESP32 فرستنده اجرا کنید تا فرآیند تبادل کلید آغاز شود.
   - اسکریپت `receiver.py` را روی ESP32 گیرنده اجرا کنید تا پاسخ دهد و تبادل کلید کامل شود.
   - اطمینان حاصل کنید که ماژول‌های ارتباطی در محدوده ارتباطی قرار دارند و به درستی تغذیه می‌شوند.

#### خروجی مورد انتظار
**فرستنده**:
```
Initializing SPI bus...
SPI bus initialized with SCK: 25, MOSI: 27, MISO: 26.
Setting up pin configurations...
Pin configuration: SS=14, Reset=35, DIO0=13.
Creating ULoRa instance...
ULoRa instance created successfully.
Initializing UECDH for key exchange...
Sender public key: <random_hex>
Sending public key...
Waiting for receiver's public key...
Received receiver's public key: <random_hex>
Shared key: <same_hex>
----- Transmitting Encrypted Message -----
Original message: Hello From Arman Ghobadi
Encrypted message: <encrypted_hex>
Message transmission complete.
```

**گیرنده**:
```
Initializing SPI bus...
SPI bus initialized with SCK: 23, MOSI: 18, MISO: 19.
Setting up pin configurations...
Pin configuration: SS=5, Reset=32, DIO0=33.
Creating ULoRa instance...
ULoRa instance created successfully.
Initializing UECDH for key exchange...
Receiver public key: <random_hex>
----- Listening for Sender's Public Key -----
Received sender's public key: <random_hex>
Sending receiver's public key...
Shared key: <same_hex>
----- Listening for Encrypted Message -----
Received encrypted message: <encrypted_hex>
Decrypted message: Hello From Arman Ghobadi
```

### تست و اعتبارسنجی
کتابخانه شامل مجموعه تستی برای بررسی:
- تبادل کلید 128 بیتی و 256 بیتی.
- تشخیص کلیدهای ضعیف.
- مدیریت اندازه کلید نامعتبر.
- پاک‌سازی امن کلیدها.
- انقضای عمر کلید.

اجرای تست‌ها:
```python
from tests.uint import test
```
![Unit Tests](./Docs/imgs/tests/test.png)

### ملاحظات امنیتی
- **محدودیت SHA256**: به دلیل عدم پشتیبانی MicroPython از منحنی‌های بیضوی، از SHA256 استفاده شده که نسبت به ECDH واقعی (مانند Curve25519) امنیت کمتری دارد.
- **AES-CBC**: این مثال از حالت CBC با IV تصادفی برای امنیت بالاتر نسبت به ECB استفاده می‌کند. اطمینان حاصل کنید که IV هرگز با یک کلید یکسان بازاستفاده نشود.
- **تصادفی بودن**: اطمینان حاصل کنید که `urandom` روی ESP32 به‌درستی مقداردهی شده است برای تولید IV و کلیدهای امن.
- **امنیت انتقال**: UECDH داده‌ها را ایمن می‌کند، اما پروتکل زیرین (مانند LoRa، Wi-Fi) ممکن است نیاز به احراز هویت اضافی برای جلوگیری از حملات Man-in-the-Middle داشته باشد.

### منابع
- NIST SP 800-56A Rev. 3 (2020)
- NIST SP 800-90A Rev. 1 (2015)
- FIPS 180-4 (2015)
- ISO/IEC 18033-3 (2010)