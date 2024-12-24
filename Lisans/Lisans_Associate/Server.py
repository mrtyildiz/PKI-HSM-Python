from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Özel anahtarınızı yükleyin
with open("private_key.pem", "rb") as key_file:
    private_key = load_pem_private_key(key_file.read(), password=None)

# Lisans bilgilerini hazırlayın ve imzalayın
with open("license_info.json", "r") as key_file:
    license_info = key_file
print(license_info)
#license_info = "license_information_here"
signature = private_key.sign(
    license_info.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
