from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509.oid import NameOID
import datetime

# Özel anahtar (private key) oluşturma
private_key = rsa.generate_private_key(
   public_exponent=65537,
   key_size=2048,
   backend=default_backend()
)

# Özel anahtarı bir dosyaya kaydetme
with open("private_key.pem", "wb") as private_key_file:
   private_key_pem = private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.NoEncryption()
   )
   private_key_file.write(private_key_pem)

# Sertifika oluşturma
subject = issuer = x509.Name([
   x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
   x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
   x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
   x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Company"),
   x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
])
certificate = x509.CertificateBuilder().subject_name(
   subject
).issuer_name(
   issuer
).public_key(
   private_key.public_key()
).serial_number(
   x509.random_serial_number()
).not_valid_before(
   datetime.datetime.utcnow()
).not_valid_after(
   datetime.datetime.utcnow() + datetime.timedelta(days=365)
).sign(private_key, SHA256(), default_backend())

# Sertifikayı bir dosyaya kaydetme
with open("certificate.pem", "wb") as certificate_file:
   certificate_pem = certificate.public_bytes(
       encoding=serialization.Encoding.PEM
   )
   certificate_file.write(certificate_pem)
