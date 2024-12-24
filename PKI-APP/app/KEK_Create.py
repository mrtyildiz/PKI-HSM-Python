from PyKCS11 import PyKCS11Lib, Mechanism
from PyKCS11.LowLevel import CKM_AES_KEY_GEN, CKO_SECRET_KEY, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_ENCRYPT, CKA_DECRYPT
from PyKCS11 import *
slot = 0
pin = "1111"
pkcs11_lib = '/lib64/libprocryptoki.so'   # HSM PKCS#11 kütüphanesinin yolu
pkcs11 = PyKCS11Lib()
pkcs11.load(pkcs11_lib)
session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login(pin)
int_len = int(256)
# KEK oluşturma
kek_template = [
    (CKA_CLASS, CKO_SECRET_KEY),
    (CKA_KEY_TYPE, CKK_AES),
    (CKA_VALUE_LEN, int_len),  # AES-256 için 32 byte
    (CKA_ENCRYPT, True),
    (CKA_DECRYPT, True)
]
kek = session.generateKey(CKM_AES_KEY_GEN, kek_template)

