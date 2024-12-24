from PyKCS11 import *
import hashlib
import os

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

# slot = 0
# pin = "1111"
# UserName = "murat1"
# Parola = "abcdefghi"
# User_Obje_Verifty_Func(slot,pin,UserName,Parola)