import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from PyKCS11 import *
from PyKCS11.LowLevel import CKM_ECDSA_KEY_PAIR_GEN
from cryptography.hazmat.backends import default_backend 
pkcs11_lib = "/lib64/libprocryptoki.so"  # Update with your PKCS#11 library path
token_label = "PKI_Test"  # Update with your token label
pin = "1111"  # Update with your PIN

pkcs11 = PyKCS11Lib()
pkcs11.load(pkcs11_lib)

slots = pkcs11.getSlotList()

slot = pkcs11.getSlotList(tokenPresent=True)[3]

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login(pin)



# Generate ECDSA key pair
mechanism = Mechanism(CKM_ECDSA_KEY_PAIR_GEN)
ec_params = Mechanism(CKM_ECDSA_KEY_PAIR_GEN)

# Generate ECDSA key pair using cryptography
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Convert keys to PKCS#11 format
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Import private key
priv_key = session.createObject([
    (CKA_CLASS, CKO_PRIVATE_KEY),
    (CKA_KEY_TYPE, CKK_EC),
    (CKA_TOKEN, True),
    (CKA_PRIVATE, True),
    (CKA_SENSITIVE, True),
    (CKA_EXTRACTABLE, True),
    (CKA_LABEL, "YourECKeyLabel"),
    (CKA_EC_PARAMS, b'\x06\x08*\x86H\xce\x3d\x02\x01\x06'),  # ECDSA SECP256R1 parameters
    (CKA_VALUE, private_key_bytes),
])

# Import public key
pub_key = session.createObject([
    (CKA_CLASS, CKO_PUBLIC_KEY),
    (CKA_KEY_TYPE, CKK_EC),
    (CKA_TOKEN, True),
    (CKA_PRIVATE, False),
    (CKA_LABEL, "YourECKeyLabel"),
    (CKA_EC_PARAMS, b'\x06\x08*\x86H\xce\x3d\x02\x01\x06'),  # ECDSA SECP256R1 parameters
    (CKA_VALUE, public_key_bytes),
])

print("ECDSA key pair successfully imported into HSM.")
# Convert the PKCS#11 private key to an EC private key
priv_key_info = session.getAttributeValue(priv_key, [CKA_EC_PRIVATE_KEY])[0]
ec_key = ec.derive_private_key(int.from_bytes(priv_key_info, byteorder='big'), ec.SECP256R1(), default_backend())

# Create X.509 certificate
subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
builder = x509.CertificateBuilder().subject_name(subject_name)
builder = builder.issuer_name(subject_name).not_valid_before(datetime.datetime.utcnow())
builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(ec_key.public_key())
builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

cert = builder.sign(ec_key, hashes.SHA256(), default_backend())

# Write X.509 certificate to a file
with open("example_cert.pem", "wb") as cert_file:
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
