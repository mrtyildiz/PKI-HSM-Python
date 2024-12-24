
from PyKCS11 import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import os
# PKCS#11 modül yüklenir

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
    EC_PEM += "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAE"+str(modulus_str[4:32])+"\n"
    EC_PEM += str(modulus_str[32:68]) +"\n"
    EC_PEM += "-----END PUBLIC KEY-----"
    print(EC_PEM)
    session.closeSession()
Slot_ID = 3
Pub_KeyName = "ansiX9p384r12pub"
a = EC_PEM_Export(Slot_ID,Pub_KeyName)
print(a)
