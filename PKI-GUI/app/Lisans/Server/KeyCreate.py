from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# RSA anahtar çiftini oluştur
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Özel anahtarı (private key) serileştir
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Açık anahtarı (public key) serileştir
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Anahtarları string olarak kaydet
private_key_str = private_pem.decode('utf-8')
public_key_str = public_pem.decode('utf-8')

private_key_str, public_key_str

with open('./private.key', 'w') as private_file:
    private_file.write(private_key_str)

with open('./public.key', 'w') as public_file:
    public_file.write(public_key_str)