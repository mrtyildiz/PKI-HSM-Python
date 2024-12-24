from PyKCS11 import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import os

def EC_PEM_Export(Slot_ID, Pub_KeyName):
    HSM_SO_File = os.environ.get('PYKCS11LIB')
    pkcs11 = PyKCS11Lib()
    pkcs11.load(HSM_SO_File)  # PKCS#11 kütüphanesinin yolu

    # Slot (yuvaya) bağlanır
    slots = pkcs11.getSlotList()
    slot = slots[Slot_ID]  # İlk slotu kullanalım

    # Token üzerinde oturum açılır
    session = pkcs11.openSession(slot)

    # Anahtarları ve objeleri listeler
    objects = session.findObjects(template=[
        (CKA_LABEL, Pub_KeyName)
        # Diğer özellikleri ekleyebilirsiniz
    ])

    if not objects:
        Error_Result = "No public key found."
        print(Error_Result)
        session.closeSession()
        exit()

    # İlk public anahtarı alır
    public_key = objects[0]

    # Public anahtarı export eder
    EC_POINT = session.getAttributeValue(public_key, [CKA_EC_POINT])

    # Public anahtar bilgilerini kontrol eder
    if None in EC_POINT:
        Error_Result = "Failed to retrieve public key information."
        print("Failed to retrieve public key information.")
        session.closeSession()
        exit()

    modulus_bytes = bytes(EC_POINT[0])
    modulus_str = base64.b64encode(modulus_bytes).decode('ascii')
    EC_PEM = "-----BEGIN PUBLIC KEY-----\n"
    EC_PEM += "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAE" + str(modulus_str[4:32]) + "\n"
    EC_PEM += str(modulus_str[32:68]) + "\n"
    EC_PEM += "-----END PUBLIC KEY-----"

    # PEM formatındaki public key'i yükleyerek EllipticCurvePublicKey objesini oluşturma
    ec_public_key = serialization.load_pem_public_key(
        EC_PEM.encode(),  # PEM verisini bytes'a çevirme
        backend=default_backend()
    )

    # Geçici bir EC anahtar çifti oluştur
    temp_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    temp_public_key = temp_private_key.public_key()

    # CSR için konu bilgilerini ayarlama
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'TR')  # Değiştirilmesi gereken kısım
    ])

    # CSR oluşturma
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(temp_private_key, hashes.SHA256(), default_backend())
    )

    # CSR'ı DER formatına çevir
    csr_der = csr.public_bytes(serialization.Encoding.PEM)

    print(csr_der.decode('utf-8'))
    session.closeSession()

# Örnek kullanım
Slot_ID = 3
Pub_KeyName = "ansiX9p384r12pub"
EC_PEM_Export(Slot_ID, Pub_KeyName)
