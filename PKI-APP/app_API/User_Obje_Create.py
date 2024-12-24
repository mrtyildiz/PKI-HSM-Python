from PyKCS11 import *
import hashlib
import os
import random
import string


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

# slot = 0
# pin = "1111"
# UserName = "murat1"
# Parola = "murat1"
# User_Obje_Create_Func(slot,pin,UserName,Parola)