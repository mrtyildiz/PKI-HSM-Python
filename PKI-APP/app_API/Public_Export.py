import os
from PyKCS11 import *
import base64
from PyKCS11 import PyKCS11
def PublicExport(Slot_id,Slot_pin,key_label):
    try:
        pkcs11_lib_path = os.environ.get('HSM_SO_File')  # HSM'nizin kütüphane yolunu değiştirin
            # PKCS11 modülünü yükle
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
            # Token'ı al
        slot = pkcs11.getSlotList(tokenPresent=True)[Slot_id]
        Slot_List = pkcs11.getSlotList(tokenPresent=True)
        token = pkcs11.getTokenInfo(slot)
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        # session.login(Slot_pin)  # HSM'ye özgü PIN'i belirtin
        try:
            session.login(Slot_pin)  # HSM'ye özgü PIN'i belirtin
            # Public anahtarı alın
            key_class = CKO_PUBLIC_KEY  # Public anahtar sınıfı
            key_type = CKK_RSA  # RSA public anahtar tipi (örneğin, CKK_RSA, CKK_ECDSA, vb.)
            # Anahtarları listeleyin ve etiketine göre arayın
            key_handles = session.findObjects([(CKA_CLASS, key_class), (CKA_KEY_TYPE, key_type), (CKA_LABEL, key_label)])
            if not key_handles:
                message = "No public key with the specified tag was found."
                session.logout()
                session.closeSession()
            else:
            # İlk public anahtarı alın
                public_key = key_handles[0]
                # Anahtarı CKA_VALUE (anahtarın değeri) özniteliğini kullanarak alın
                attributes = session.getAttributeValue(public_key, [CKA_MODULUS])[0]
                modulus_bytes = bytes(attributes)
                modulus_str = base64.b64encode(modulus_bytes).decode('ascii')
                modulus_news = modulus_str[:-2]
                public_key = f'-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA{modulus_news}IDAQAB-----END PUBLIC KEY-----'
                public_key_Array = []
                public_key_Array.append(public_key[0:26])
                public_key_Array.append(public_key[26:90])
                public_key_Array.append(public_key[90:154])
                public_key_Array.append(public_key[154:218])
                public_key_Array.append(public_key[218:282])
                public_key_Array.append(public_key[282:346])
                public_key_Array.append(public_key[346:410])
                public_key_Array.append(public_key[410:418])
                public_key_Array.append(public_key[418:442])
                # Open a file in write mode (you can specify the file path)
                ROOT_DIR = "/app/Public/"
                file_path = str(ROOT_DIR)+str(key_label)+'.pem'
                with open(file_path, 'w') as file:
                    # Convert the array elements to strings and write them to the file
                    for line in public_key_Array:
                        file.write(str(line) + '\n')
                message = f'Created public key named {key_label}'
                session.logout()
                session.closeSession()
            # return file_path
        except:
            message = "PIN Error"
            # Diğer PyKCS11Error hatalarını tekrar fırlat
    except:
        message = "Slot_ID Error"
        #pass
    return message

# Slot_id = 0
# Slot_pin ="1111"
# key_label = 'CAKeyspubss'  # Anahtar etiketi
# a = PublicExport(Slot_id,Slot_pin,key_label)
# print(a)