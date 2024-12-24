from PyKCS11 import *
import os
import base64
import OpenSSL.crypto
from datetime import datetime
import json
import hashlib

def User_Infos(slot_id,Slot_pin):
    # HSM PKCS#11 kütüphanesinin yolunu belirtin
    pkcs11_lib_path = os.environ.get('HSM_SO_File')  # HSM'nizin kütüphane yolunu değiştirin
    # PKCS11 modülünü yükle
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib_path)
    # Token'ı al
    slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
    token = pkcs11.getTokenInfo(slot)
    
    # Oturumu aç (örneğin, 1111 şifresi ile)
    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    #session.login(Slot_pin)  # HSM'ye özgü PIN'i belirtin
    # JSON verisi için boş bir liste oluşturun
    json_user = []
    # Sertifikaları listele
    User_All = session.findObjects([(CKA_CLASS, CKO_DATA)])

    for user in User_All:
        UserName = session.getAttributeValue(user, [CKA_LABEL])[0]
        Password = session.getAttributeValue(user, [CKA_VALUE])[0]
        Password_bytes = bytes(Password)
        password_str = Password_bytes.decode('utf-8')
        # SHA-256 hash objesini oluşturun
        hash_objesi = hashlib.sha256()

        # Veriyi hash objesine güncelleyin
        hash_objesi.update(password_str.encode())

        # SHA-256 hash değerini hesaplayın
        hash_degeri = hash_objesi.hexdigest()
        Token_Name = token.label
        Token = Token_Name.replace(" ", "")
        Json_user_single = {"Slot_ID":slot_id, "Token_Name": Token, "UserName": UserName, "Password": hash_degeri}
        json_user.append(Json_user_single)
    # session.logout()
    # session.closeSession()
    return json_user

# slot_id = 0
# Slot_pin = "1111"
# a = User_Info(slot_id,Slot_pin)
# print(a)