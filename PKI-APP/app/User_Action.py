from PyKCS11 import *
import hashlib
import os
import random
import string
import base64
import OpenSSL.crypto
from datetime import datetime
import json

def User_Obje_Create_Func(slot,pin,UserName,Parola):
    try:

        pkcs11_lib = os.environ.get('HSM_SO_File')  # HSM PKCS#11 kütüphanesinin yolu
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib)
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        # session.login(pin)
        # Parolayı özetleme (Hashing)
        hash_parola = Parola.encode('utf-8')
        print(hash_parola)
        # Sabitleri PyKCS11 modülünden alın
        CKA_CLASS = PyKCS11.CKA_CLASS
        CKA_TOKEN = PyKCS11.CKA_TOKEN
        CKA_PRIVATE = PyKCS11.CKA_PRIVATE
        CKA_MODIFIABLE = PyKCS11.CKA_MODIFIABLE
        CKA_LABEL = PyKCS11.CKA_LABEL
        CKA_VALUE = PyKCS11.CKA_VALUE

        CKA_ID = PyKCS11.CKA_OBJECT_ID

        id = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))

        hash_id = hashlib.sha1(id.encode()).digest()
        # Kullanıcıyı HSM'de oluşturma
        kullanici = session.createObject([
            (CKA_CLASS, CKO_DATA),
            (CKA_TOKEN, True),
            (CKA_PRIVATE, False),
            (CKA_MODIFIABLE, True),
            (CKA_LABEL, UserName),
            (CKA_VALUE, hash_parola),
            (CKA_ID, hash_id)
        ])
        session.logout()
        session.closeSession()
        result = "User Create"
        return result
    except:
        result = "User Not Create"
        return result

def User_Obje_Verifty_Func(slot,pin,UserName,Parola):
    pkcs11_lib = os.environ.get('HSM_SO_File')  # HSM PKCS#11 kütüphanesinin yolu
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib)
    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login(pin)
    # Parolayı özetleme (Hashing)
    hash_parola = Parola.encode('utf-8')

    # Kullanıcıyı HSM'den sorgulama
    objects = session.findObjects([(CKA_CLASS, CKO_DATA), (CKA_LABEL, UserName)])
    if len(objects) == 0:
        print("Kullanıcı bulunamadı.")
        result = "Not found user"

    else:
        kullanici_nesnesi = objects[0]
        stored_hash_parola = session.getAttributeValue(kullanici_nesnesi, [CKA_VALUE])[0]
        parola_CKA = ""
        for i in range(len(stored_hash_parola)):
            character = chr(stored_hash_parola[i])
            parola_CKA = parola_CKA + str(character)
        print(parola_CKA)
        print(hash_parola)
        stored_parola_bytes = parola_CKA.encode('utf-8')
        if hash_parola == stored_parola_bytes:
            print("Kullanıcı doğrulandı.")
            result = "User Verfty"
            #return result
        else:
            print("Parola yanlış.")
            result = "User Not Verfty"
           # return result
    # Oturumu kapat
    session.logout()
    session.closeSession()
    return result


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