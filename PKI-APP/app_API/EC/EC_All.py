from PyKCS11 import *
from PyKCS11.LowLevel import CKA_ID, CKM_ECDSA_KEY_PAIR_GEN
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from asn1crypto.keys import ECDomainParameters, NamedCurve
# HSM'nin PKCS#11 kütüphanesi dosya yolu
pkcs11_library_path = "/lib64/libprocryptoki.so"

# Kullanıcının PIN'i
pin = "1111"

# Kullanılacak slot ID'si
slot_id = 3

# PKCS11 nesnesini oluşturun
pkcs11 = PyKCS11Lib()
pkcs11.load(pkcs11_library_path)

# Slot'a bağlan
slot = pkcs11.getSlotList()[slot_id]

# PIN ile giriş yap
session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login(pin)
# EC anahtarı oluşturun
# Setup the domain parameters, unicode conversion needed for the curve string
curve = "1.2.840.10045.3.1.7"
label = 'pkideneme'
domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
ec_params = domain_params.dump()
pub_key_label = label + "pub"
priv_key_label = label + "priv"
# EC public key template
ec_public_tmpl = [
    (CKA_CLASS, CKO_PUBLIC_KEY),
    (CKA_PRIVATE, CK_FALSE),
    (CKA_TOKEN, CK_TRUE),
    (CKA_ENCRYPT, CK_TRUE),
    (CKA_VERIFY, CK_TRUE),
    (CKA_WRAP, CK_TRUE),
    (CKA_KEY_TYPE, CKK_ECDSA),
    (CKA_EC_PARAMS, ec_params),
    (CKA_LABEL, pub_key_label.encode()),
]

# EC private key template
ec_priv_tmpl = [
    (CKA_CLASS, CKO_PRIVATE_KEY),
    (CKA_KEY_TYPE, CKK_ECDSA),
    (CKA_TOKEN, CK_TRUE),
    (CKA_DECRYPT, CK_TRUE),
    (CKA_SIGN, CK_TRUE),
    (CKA_UNWRAP, CK_TRUE),
    (CKA_LABEL, priv_key_label.encode()),
]

# EC anahtarı çiftini oluşturun
(pub_key, priv_key) = session.generateKeyPair(ec_public_tmpl, ec_priv_tmpl, mecha=CKM_ECDSA_KEY_PAIR_GEN)

# CKA_VALUE değerini alın
private_key_info = session.getAttributeValue(priv_key, [CKA_VALUE])[0]

# ECDSA private key'i yükleyin
private_key = serialization.load_der_private_key(private_key_info, password=None, backend=default_backend())

# CSR oluşturun
subject = x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Example Corp"),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com"),
])

csr = x509.CertificateSigningRequestBuilder().subject_name(
    subject
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("example.com")]),
    critical=False,
).sign(private_key, hashes.SHA256(), default_backend())

# CSR'ı dosyaya kaydedin
with open("example.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# CSR'ı imzalayarak CRT oluşturun
certificate = x509.CertificateBuilder().subject_name(
    csr.subject
).issuer_name(
    csr.subject
).public_key(
    csr.public_key()
).serial_number(
    1
).not_valid_before(
    csr.not_valid_before
).not_valid_after(
    csr.not_valid_after
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("example.com")]),
    critical=False,
).sign(private_key, hashes.SHA256(), default_backend())

# CRT'ı dosyaya kaydedin
with open("example.crt", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

# Oturumu kapat
session.logout()
session.closeSession()
