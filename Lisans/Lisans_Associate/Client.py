from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_license(license_info, signature):
    try:
        # Genel anahtarınızı yükleyin
        with open("public_key.pem", "rb") as key_file:
            public_key = load_pem_public_key(key_file.read())

        # İmzayı doğrulayın
        public_key.verify(
            signature,
            license_info.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Kullanımı
is_valid = verify_license("license_information_here", signature_from_server)
if not is_valid:
    # Lisans geçersiz işlem
    pass
