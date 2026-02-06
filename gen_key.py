from cryptography.fernet import Fernet

# Generate the key
key = Fernet.generate_key()
with open("symmetric.key", "wb") as f:
    f.write(key)
print("Symmetric key generated.")
