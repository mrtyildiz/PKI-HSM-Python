from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def encrypt(message, key):
    """
    AES-CFB ile metni şifreler.
    """
    key_bytes = base64.b64decode(key)
    iv = b'\x00' * 16  # Initialization Vector
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext, key):
    """
    AES-CFB ile şifrelenmiş metni çözer.
    """
    key_bytes = base64.b64decode(key)
    iv = b'\x00' * 16  # Initialization Vector
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

# # Rastgele AES anahtarı
# aes_key = "V2FiYm8gTGVuZ3RoIFRoZSBEYXRh"

# # Metni şifrele
# plaintext = "Merhaba, bu metin şifrelenmiştir!"
# encrypted_text = encrypt(plaintext, aes_key)
# print(f"Şifrelenmiş Metin: {encrypted_text}")

# # Şifreli metni çöz
# decrypted_text = decrypt(encrypted_text, aes_key)
# print(f"Çözülen Metin: {decrypted_text}")
