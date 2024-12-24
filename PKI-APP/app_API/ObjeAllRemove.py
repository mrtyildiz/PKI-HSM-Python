from PyKCS11 import *
from PyKCS11.LowLevel import *
import os


def RemoveObje(slot_id,slot_pin):
    # HSM PKCS#11 kütüphanesinin yolunu belirtin
    pkcs11_lib_path = os.environ.get('HSM_SO_File')  # HSM'nizin kütüphane yolunu değiştirin
        # PKCS11 modülünü yükle
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib_path)
        # Token'ı al
    slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]

    # Oturumu aç (örneğin, 1111 şifresi ile)
    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login(slot_pin)  # HSM'ye özgü PIN'i belirtin
    All = session.findObjects()
    for obje in All:
        session.destroyObject(obje)

    
    session.logout()
    session.closeSession()


