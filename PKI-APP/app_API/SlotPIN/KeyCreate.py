from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
import os

def generate_and_save_key(file_path):
    # Generate a random 256-bit (32-byte) AES key
    aes_key = os.urandom(32)

    # Save the key to the file
    with open(file_path, 'wb') as file:
        file.write(aes_key)

    return aes_key

# Example usage:
key_file_path = "keySlot"

# Generate and save the key
generated_key = generate_and_save_key(key_file_path)

print(f"Generated AES Key: {generated_key.hex()}")
print(f"AES Key saved to: {key_file_path}")
