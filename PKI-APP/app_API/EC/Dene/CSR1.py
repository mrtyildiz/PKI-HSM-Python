from pkcs11 import PKCS11
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

# HSM ile iletişim için PKCS11 nesnesini oluşturun
pkcs11 = PKCS11("/lib64/libprocryptoki.so")

# Kullanıcı kimliği (User ID) ve PI
pin = "1111"

# Kullanıcı tarafından seçilen bir slot ID'si
selected_slot_id = 0  # Bu değeri HSM'nize göre güncelleyin

# Slot'a bağlan
session = pkcs11.openSession(selected_slot_id, CKF_SERIAL_SESSION)

try:
    # Kullanıcı kimliği ve PIN ile giriş yap
    session.login(pin, CKU_USER)

    # ECDSA anahtarı oluşturun
    private_key = session.generateKeyPair(ec.ECDSA, {'ecParams': ec.SECP256R1}, {'token': False}, {'verify': True, 'sign': True},)

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
    crt = csr.public_bytes(serialization.Encoding.PEM)

    # CRT'ı dosyaya kaydedin
    with open("example.crt", "wb") as f:
        f.write(crt)

finally:
    # Oturumu kapat
    session.logout()
    session.closeSession()
