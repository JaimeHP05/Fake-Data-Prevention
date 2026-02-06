# System Security Project
**Fake Data Prevention with Conventional Cryptotools**

*Demonstration of how to prevent the injection of fake data into a system using asymmetric cryptography (RSA) and JSON Web Tokens (JWT).*

**Authors:**
* Jaime Hernández Pérez (583770)
* Maciej Wieteska (579536)

---

## 📖 Index
1. Core Components & Roles
2. Libraries & Tools
3. Commands
4. Python Code
5. Demonstration Results

---

## 1. Core Components & Roles

* **Issuer:** Generates commands, encrypts the sensitive payload for confidentiality (AES), and signs the token using a Private Key (RSA) for authenticity.
* **Receiver:** Validates the sender's identity using a trusted Digital Certificate (X.509) and decrypts the payload (only if the signature is valid).
* **Attacker:** Intercepts the token but fails to inject fake data because they lack the Private Key to sign the forgery, and fails to read the command because they lack the Symmetric Key to decrypt it.

---

## 2. Libraries & Tools

### pyjwt
* **Standardization:** It packs our data into the official JWT format (`Header.Payload.Signature`) so it is easy to transmit.
* **Verification:** It checks the signature math and enforces the rule to only accept RS256 tokens. This blocks the hacker from tricking the system with a weaker algorithm.

### cryptography
* **Confidentiality (Fernet):** Applies AES encryption. It turns the command "OPEN_GATE" into unreadable gibberish (`gAAAA...`) so the hacker cannot see what is being sent.
* **Identity (X.509):** Instead of using raw keys, this library reads Digital Certificates. It extracts the public key from the certificate file, allowing for professional verification of the sender's identity.

---

## 3. Commands

Run the following commands in the terminal to generate the necessary keys and certificates:

### 1. Generate Symmetric Key
~~~bash
python3 gen_key.py
~~~


### 2. Generate RSA Private Key
Generates a 2048-bit private key.
~~~bash
openssl genrsa -out private_key.pem 2048
~~~


### 3. Generate Digital Certificate
Extracts the public key, adds identity information, and signs the certificate.
~~~bash
openssl req -new -x509 -key private_key.pem -out certificate.crt -days 365
~~~
*(Enter your details when prompted, e.g., Country: ES, Org: Security Project)*

---

## 4. Python Code

### `issuer.py`
Simulates the server sending a secure command.
~~~python
import jwt
import datetime
from cryptography.fernet import Fernet

# Load Symmetric Key (Encryption)
with open("symmetric.key", "rb") as k:
    cipher_suite = Fernet(k.read())

# Load Private Key (Digital Signature)
try:
    with open("private_key.pem", "rb") as f:
        private_key = f.read()
except FileNotFoundError:
    print("ERROR: private_key.pem not found. Run OpenSSL commands first.")
    exit()

raw_command = "OPEN_MAIN_GATE"
encrypted_command = cipher_suite.encrypt(raw_command.encode()).decode()

# Define the Data Payload
data_payload = {
    "user": "sys_admin",
    "role": "superuser",
    "command": encrypted_command,
    "amount": 10000,
    "timestamp": str(datetime.datetime.now())
}

print(f"--- ISSUER: Generating Token ---")
print(f"Original Data: {data_payload}")
print(f"Raw Command: {raw_command}")

# Sign the data and create the JWT
signed_token = jwt.encode(
    payload=data_payload,
    key=private_key,
    algorithm="RS256"
)

print(f"Generated Token: {signed_token[:20]}... (truncated)")

# Simulate Network Transmission
with open("token_transmission.txt", "w") as f:
    f.write(signed_token)

print("Status: Token sent to network.\n")
~~~


### `receiver.py`
Simulates the device verifying and executing the command.
~~~python
import jwt
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.backends import default_backend

print("--- RECEIVER: Processing Data ---")

# Load Certificate and Extract Public Key
try:
    with open("certificate.crt", "rb") as f:
        cert_pem = f.read()
        certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
        public_key = certificate.public_key()
except FileNotFoundError:
    print("Error: certificate.crt not found.")
    exit()

# Load Symmetric Key
try:
    with open("symmetric.key", "rb") as k:
        cipher_suite = Fernet(k.read())
except FileNotFoundError:
    print("Error: symmetric.key not found.")
    exit()

print("---RECEIVER: Symmetric Key loaded---")

# Read the token from the "network"
try:
    with open("token_transmission.txt", "r") as f:
        received_token = f.read()
except FileNotFoundError:
    print("Error: No token found in the network.")
    exit()

print(f"Token Received: {received_token[:20]}...")

# Verify the Signature and Decode
try:
    decoded_data = jwt.decode(
        jwt=received_token,
        key=public_key,
        algorithms=["RS256"]
    )

    print("\n[SUCCESS] INTEGRITY VERIFIED.")
    print("The signature is valid. Executing command:")
    
    encrypted_cmd = decoded_data['command']
    decrypted_cmd = cipher_suite.decrypt(encrypted_cmd.encode()).decode()
    print(f"Decrypted Command: {decrypted_cmd}")
    print(f"User Authorized: {decoded_data['user']}")

except jwt.InvalidSignatureError:
    print("\n[CRITICAL ERROR] SIGNATURE MISMATCH!")
    print("Security Alert: The data has been tampered with (Fake Data detected).")
    print("Action: Request Rejected.")

except Exception as e:
    print(f"\n[ERROR] Token invalid: {e}")
~~~


### `hacker.py`
Simulates the Man-in-the-Middle attack.
~~~python
import jwt

print("--- ATTACKER: Man-in-the-Middle Interception ---")

# Intercept the token
try:
    with open("token_transmission.txt", "r") as f:
        intercepted_token = f.read()
except FileNotFoundError:
    print("No token found to intercept.")
    exit()

# Decode without verification
payload_only = jwt.decode(intercepted_token, options={"verify_signature": False})

print(f"Hacker sees this Payload: {payload_only}")
print(f"\nHacker can't read the command, but will try to change it anyway")

# Inject Fake Data
payload_only["user"] = "HACKER_ENTITY"
payload_only["command"] = "FAKE_ENCRYPTED_DATA"

print(f"Modified Payload: {payload_only}")

# Forge with wrong key/algorithm
fake_key = "random-string"
forged_token = jwt.encode(payload_only, fake_key, algorithm="HS256")

# Inject forged token
with open("token_transmission.txt", "w") as f:
    f.write(forged_token)

print("\nStatus: Forged token injected.")
~~~


### `gen_key.py`
Symmetric Key generator.
~~~python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
with open("symmetric.key", "wb") as f:
    f.write(key)
print("Symmetric key generated.")
~~~


---

## 5. Demonstration Results

### Case 1: Legitimate Transaction
The Issuer sends a valid token, and the Receiver accepts it.

**Issuer Output:**
~~~text
--- ISSUER: Generating Token ---
Original Data: {'user': 'sys_admin', ... 'command': 'gAAAA...'}
Raw Command: OPEN_MAIN_GATE
Status: Token sent to network.
~~~

**Receiver Output:**
~~~text
--- RECEIVER: Processing Data ---
Token Received: eyJ0eXAiOiJKV1Qi...
[SUCCESS] INTEGRITY VERIFIED.
The signature is valid. Executing command:
Decrypted Command: OPEN_MAIN_GATE
User Authorized: sys_admin
~~~


### Case 2: Fake Data Attack
The Attacker intercepts the token, modifies the payload, and injects fake data.

**Hacker Output:**
~~~text
--- ATTACKER: Man-in-the-Middle Interception ---
Hacker sees this Payload: {'user': 'sys_admin', ... 'command': 'gAAAA...'}
Hacker can't read the command, but will try to change it anyway
Modified Payload: {'user': 'HACKER_ENTITY', ... 'command': 'FAKE_ENCRYPTED_DATA'}
Status: Forged token injected.
~~~

**Receiver Output (Defense):**
~~~text
--- RECEIVER: Processing Data ---
[ERROR] Token invalid: The specified alg value is not allowed
~~~
