from PyKCS11 import *
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def find_private_key(session, label):
    # HSM'deki özel anahtarı bulma
    private_key_template = [
        (CKA_CLASS, CKO_PRIVATE_KEY),
        (CKA_LABEL, label),
    ]

    objects = session.findObjects(private_key_template)

    if not objects:
        raise Exception("Private key not found in HSM")
    print(objects)
    private_key_handle = objects[0]
  
    return private_key_handle

# HSM ile iletişim kurma ve uygun bir slot seçme
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load()
slot = pkcs11.getSlotList(tokenPresent=True)[3]
session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("1111")

# HSM'deki özel anahtarı bulma
key_label = "DenemeEC3"
private_key_handle = find_private_key(session, key_label)
print(dir(private_key_handle))
print(private_key_handle)

session.logout()
session.closeSession()
