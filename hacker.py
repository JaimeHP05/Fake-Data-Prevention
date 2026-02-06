import jwt
import json
import base64

print("--- ATTACKER: Man-in-the-Middle Interception ---")

# Intercept the token from the transmission file
try:
	with open("token_transmission.txt", "r") as f:
		intercepted_token = f.read()
except FileNotFoundError:
	print("No token found to intercept.")
	exit()

# Decoding the JWT without a key
payload_only = jwt.decode(intercepted_token, options={"verify_signature": False}) 
# verify=False because the hacker doesn't have the Public Key, so it shows what's inside

print(f"Hacker sees this Payload: {payload_only}")
# The hacker sees: "command": "gAAAAABl..."

# Since they don't have symmetric.key, they don't know what it says
print(f"\nHacker can't read the command, but will try to change it anyway")

# Injecting Fake Data
payload_only["user"] = "HACKER_ENTITY"
payload_only["command"] = "FAKE_ENCRYPTED_DATA" 

print(f"Modified Payload: {payload_only}")

# Attempting to forge the token
# The hacker doesn't have 'private_key.pem', so they sign it with a fake key
fake_key = "random-string"
forged_token = jwt.encode(payload_only, fake_key, algorithm="HS256") # Wrong algorithm too

# Inject the forged token back into the network
with open("token_transmission.txt", "w") as f:
	f.write(forged_token)

print("\nStatus: Forged token injected.")
