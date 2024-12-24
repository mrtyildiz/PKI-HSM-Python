from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex
import os
from PyKCS11 import *
import base64
from PyKCS11 import PyKCS11
import json
import hashlib
from PyKCS11.LowLevel import *


HSM_SO_File = os.environ.get('PYKCS11LIB')

def AESEncrypt(ID,PIN,KeyName,Data,init_Vector_str):
    try:
        Bytes_Data = Data.encode('utf-8')
        iv_bytes = bytes.fromhex(init_Vector_str) 
        with HsmClient(slot=ID, pin=PIN, pkcs11_lib=HSM_SO_File) as c:
            handles = c.get_object_handle(label=KeyName)
            ciphertext = c.encrypt(handle=handles,
                                data=Bytes_Data,
                                mechanism=HsmMech.AES_CBC_PAD,
                                iv=iv_bytes)
            encrypt_data = bytes_to_hex(ciphertext)
        result = {"Encrypt Data: " : encrypt_data}
    except:
        error = "HSM is error"
        result = {"Error: " : error}
    return result



def AESDEcryption(ID,PIN,KeyName,Data,init_Vector_str):
    try:
        with HsmClient(slot=ID, pin=PIN, pkcs11_lib=HSM_SO_File) as c:
            handles = c.get_object_handle(label=KeyName)
            init_vector = bytes.fromhex(init_Vector_str)
            byte_data = bytes.fromhex(Data)
            cleartext = c.decrypt(handle=handles, data=byte_data, mechanism=HsmMech.AES_CBC_PAD, iv=init_vector)

            Decrypt_Data = cleartext.decode('utf-8')
        result = {"Decrypt Data: " : Decrypt_Data}
    except:
        error = "HSM is error"
        result = {"Error: " : error}
    return result



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

def CrtExport(Slot_ID,ca_cert_label):
    try:
        lib = os.environ.get('HSM_SO_File')  # HSM kütüphanesinin yolunu güncelleyin
        pkcs11 = PyKCS11Lib()
        pkcs11.load(lib)
        slot = pkcs11.getSlotList()[Slot_ID]  # HSM cihazının yuvasını seçin
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)  # Oturum açın
        # CA sertifikasının etiketini belirtin
        try:
            ca_cert = session.findObjects([
                (CKA_LABEL, ca_cert_label),
                (CKA_CLASS, CKO_CERTIFICATE)
            ])[0]
            cert_der = session.getAttributeValue(ca_cert, [CKA_VALUE])[0]  # DER formatında sertifika değerini alın
            cert_der_bytes = bytes(cert_der)
            #print(cert_der)
            cert_pem = '-----BEGIN CERTIFICATE-----\n'
            cert_pem += base64.b64encode(cert_der_bytes).decode('ascii')
            cert_pem += '\n-----END CERTIFICATE-----\n'
            #print(cert_pem)
            # PEM dosyasını kaydetme
            FileName = ca_cert_label +".crt"
            # Dosyanın kaydedileceği dizin
            save_directory = "/app/CRT"
            # Tam dosya yolunu oluşturun
            full_file_path = os.path.join(save_directory, FileName)
            with open(full_file_path, 'w') as pem_file:
                pem_file.write(cert_pem)
            session.closeSession()  # Oturumu kapatı
            message = f'Created public key named {FileName}'
        # return full_file_path
        except:
            message = "No public key with the specified tag was found."
    except:
        message = "Slot_ID Error"
    return message

def Check_Token(target_label):
    # PKCS#11 uyumlu cihazın kütüphane yolunu belirtin
    library_path = os.environ.get('PYKCS11LIB')
    # PKCS#11 modülünü yükle
    pkcs11 = PyKCS11Lib()
    pkcs11.load(library_path)
  #  Slot_List = pkcs11.getSlotList(tokenPresent=True)
    # PKCS#11 uyumlu cihazları listeleyin
    try:
        slots = pkcs11.getSlotList()

        if not slots:
            print("Hiçbir PKCS#11 uyumlu cihaz bulunamadı.")
            exit()
        # Her bir slotta tokenları kontrol edin 
        target_label_array = char_list = [char for char in target_label]

        for slot in slots:
            token = pkcs11.getTokenInfo(slot)
            label = token.label
            new_label = label.replace(' ', '')
            if new_label.upper() == target_label.upper():
                slot_info = {
                    "slot_id": slot,
                    "slot_name": target_label
                    }
                # message = json.dumps(slot_info)
                message = slot_info
                break  # İlk eşleşen token'ı bulduktan sonra döngüden çıkabilirsiniz.
            else:
                pass
        else:
            message = "Token not found"
        return message
    except:
        message = "Token not found"
        return message

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

def Slot_Label_Func():
    try:
        pkcs11_lib_path = os.environ.get('HSM_SO_File')
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
        slots = pkcs11.getSlotList(tokenPresent=True)
        Slot_Label_Array =[]
        for i in range(len(slots)-1):
            info = pkcs11.getTokenInfo(slots[i])
            Label = info.label
            Token_Label = "".join(Label.split())
            Slot_Label_Array.append(Token_Label)
        
        return Slot_Label_Array
    except:
        result = "Failed to connect to HSM device"
        return result