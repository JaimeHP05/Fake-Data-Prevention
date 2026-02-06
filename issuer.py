import jwt
import datetime
from cryptography.fernet import Fernet # Fernet does Symmetric


# Load Symmetric Key (Encryption)
with open("symmetric.key", "rb") as k:
	cipher_suite = Fernet(k.read())

# Load Private Key (Digital Signature)
try:
	with open("private_key.pem", "rb") as f:
		# rb means read binary
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
	"amount": 10000, # Random value, imagine this is dollars in a bank
	"timestamp": str(datetime.datetime.now()) # To prevent replay attacks
}

print(f"--- ISSUER: Generating Token ---")
print(f"Original Data: {data_payload}")
print(f"Raw Command: {raw_command}")

# Sign the data and create the JWT (Authenticity & Integrity)
# Integrity - Signing - Encoding
signed_token = jwt.encode( # Create a hash of our data
	payload=data_payload,
	key=private_key,
	algorithm="RS256" # RSA Signature with SHA-256 for Asymmetric Cryptography
)

print(f"Generated Token: {signed_token[:20]}... (truncated)") # :20 for shortening

# Simulate Network Transmission
# Save token to file to simulate sending it
with open("token_transmission.txt", "w") as f:
	# In real life we would send it through an HTTP POST request (TCP/IP packets) 
	# and the hacker would sniff the packet with Proxy tools
	f.write(signed_token)

print("Status: Token sent to network.\n")
