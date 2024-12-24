from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

def read_key_from_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def encrypt(text):
    key_file_path = "/app/SlotPIN/keySlot"
    key = read_key_from_file(key_file_path)
    key = key.ljust(32)[:32]  # Ensure key length is 32 bytes
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_text = text.ljust(16 * (len(text) // 16 + 1)).encode('utf-8')  # Pad the text to be a multiple of 16 bytes
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    return b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext):
    key_file_path = "/app/SlotPIN/keySlot"
    key = read_key_from_file(key_file_path)
    key = key.ljust(32)[:32]  # Ensure key length is 32 bytes
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ciphertext_bytes = b64decode(ciphertext)
    padded_text = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    return padded_text.decode('utf-8').rstrip()

# # Örnek kullanım:
# plaintext = "1111"
# key_file_path = "./keySlot"

# # Anahtarı dosyadan oku
# encryption_key = read_key_from_file(key_file_path)

# # Şifrele
# encrypted_text = encrypt(plaintext)
# print(f"Şifrelenmiş Metin: {encrypted_text}")

# # Şifre çöz
# decrypted_text = decrypt(encrypted_text)
# print(f"Şifre Çözülmüş Metin: {decrypted_text}")
