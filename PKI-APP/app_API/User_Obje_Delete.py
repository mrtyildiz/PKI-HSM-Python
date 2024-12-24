from PyKCS11 import *
import os
import base64
import OpenSSL.crypto
from datetime import datetime
import json

def User_Delete(slot_id,Slot_pin,UserName):
    try:
        # HSM PKCS#11 kütüphanesinin yolunu belirtin
        pkcs11_lib_path = os.environ.get('HSM_SO_File')  # HSM'nizin kütüphane yolunu değiştirin
        # PKCS11 modülünü yükle
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
        # Token'ı al
        slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]        
        # Oturumu aç (örneğin, 1111 şifresi ile)
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
      #  session.login(Slot_pin)  # HSM'ye özgü PIN'i belirtin
        Obje = session.findObjects([(CKA_CLASS, CKO_DATA),(CKA_LABEL, UserName)])[0]
        session.destroyObject(Obje)
        session.logout()
        session.closeSession()
        return UserName
    except:
        return UserName
# slot_id = 0
# Slot_pin = "1111"
# UserName = "Murat"
# User_Delete(slot_id,Slot_pin,UserName)


