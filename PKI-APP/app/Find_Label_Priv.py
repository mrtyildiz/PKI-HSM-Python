from PyKCS11 import *
import hashlib
import os

def Find_Label_Obje(slot,pin,obje):
    pkcs11_lib = os.environ.get('HSM_SO_File')  # HSM PKCS#11 kütüphanesinin yolu
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib)
    Slot_ID = int(slot)
    session = pkcs11.openSession(Slot_ID, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login(pin)
    
    # Kullanıcıyı HSM'den sorgulama
    objects = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),(CKA_LABEL, obje)])

    if len(objects) == 0:
        result = "Not Found Obje"
    else:
        result = "Found Obje"
    return result
