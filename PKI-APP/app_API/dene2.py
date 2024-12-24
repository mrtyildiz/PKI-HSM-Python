from PyKCS11 import *
import hashlib
import os

def AESKeysRemove(slot,pin,Obje_Label):

    # HSM PKCS#11 kütüphanesinin yolunu belirtin
    pkcs11_lib_path = os.environ.get('HSM_SO_File')  # HSM'nizin kütüphane yolunu değiştirin
        # PKCS11 modülünü yükle
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib_path)
        # Token'ı al
    slot = pkcs11.getSlotList(tokenPresent=True)[slot]

    # Oturumu aç (örneğin, 1111 şifresi ile)
    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    #session.login(slot_pin)  # HSM'ye özgü PIN'i belirtin
    session.login(pin)
    Obje = session.findObjects([(CKA_CLASS, CKO_SECRET_KEY),(CKA_LABEL, Obje_Label)])[0]
    session.destroyObject(Obje)
    session.logout()
    session.closeSession()
    result = "Object deletion successful"


slot = 0
pin = "1111"
Obje_Label = "AESKeys5"
User_Obje_Verifty_Func(slot,pin,Obje_Label)