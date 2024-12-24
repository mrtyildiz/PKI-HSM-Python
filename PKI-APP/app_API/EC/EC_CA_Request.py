from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.x509 import Name, CertificateBuilder
from cryptography import x509
import datetime
import base64
import os
from Crypto.PublicKey import ECC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from PyKCS11 import PyKCS11Error, CKO_PRIVATE_KEY, CKA_LABEL, CKA_EC_POINT, CKA_EC_PARAMS

def EC_CARequestCertificate(Slot_ID, Slot_PIN, KeyLabel, CommonName, OrganizationName, CountryName):
    pkcs11_lib = os.environ.get('PYKCS11LIB')
    slot = Slot_ID
    pin = Slot_PIN

    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib)

    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login(pin)
    Priv_Label = KeyLabel + "priv"
    private_key_template = [
        (CKA_CLASS, CKO_PRIVATE_KEY),
        (CKA_LABEL, Priv_Label),
    ]

    private_key = session.findObjects(private_key_template)[0]
    print(private_key)
    Pub_Label = KeyLabel + "pub"
    public_key_template = [
        (CKA_CLASS, CKO_PUBLIC_KEY),
        (CKA_LABEL, Pub_Label),
    ]

    public_key = session.findObjects(public_key_template)[0]
    print(public_key)
    # # ECDSA anahtarını dışa aktar
    ec_params = session.getAttributeValue(private_key, [CKA_EC_PARAMS])[0]
    print(ec_params)
    ec_point = session.getAttributeValue(public_key, [CKA_EC_POINT])[0]
    print(int.from_bytes(ec_point, byteorder='big'))

    if None in ec_point:
        Error_Result = "Failed to retrieve public key information."
        print("Failed to retrieve public key information.")
        session.closeSession()
        exit()

    modulus_bytes = bytes(ec_point[0])
    modulus_str = base64.b64encode(modulus_bytes).decode('ascii')
    EC_PEM = "-----BEGIN PUBLIC KEY-----\n"
    EC_PEM += "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAE" + str(modulus_str[4:32]) + "\n"
    EC_PEM += str(modulus_str[32:68]) + "\n"
    EC_PEM += "-----END PUBLIC KEY-----"
    ec_public_key = serialization.load_pem_public_key(
        EC_PEM.encode(),  # PEM verisini bytes'a çevirme
        backend=default_backend()
    )
    subject = Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'organization_name'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'TR')
    ])

    builder = CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )

    # # ECDSA sign ve SHA-256 digest algoritmalarını belirtiyoruz
    # certificate = builder.sign(
    #     private_key=private_key_obj,
    #     algorithm=hashes.SHA256(),
    #     backend=default_backend()
    # )

    # print(certificate)

    session.logout()
    session.closeSession()

# Diğer kodları buraya ekleyebilirsiniz


Slot_ID = 4
Slot_PIN = "1111"
PrivateKeyName = "key"
common_name = "deneme"
OrganizationName = "deneme"
CountryName = "TR"
EC_CARequestCertificate(Slot_ID,Slot_PIN,PrivateKeyName,common_name,OrganizationName,CountryName)