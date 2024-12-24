from PyKCS11 import PyKCS11Lib
from OpenSSL import crypto
from PyKCS11 import *
from PyKCS11.LowLevel import *
import base64
import os
import OpenSSL.crypto
from datetime import datetime

def Certificate_Date(cert_path):
    try:
        with open(cert_path, 'rt') as cert_file:
            cert_data = cert_file.read()
          
            certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
            end_time = certificate.get_notAfter().decode()
            end_date_obj = datetime.strptime(end_time, "%Y%m%d%H%M%SZ")
            print(end_date_obj)
        return end_date_obj
    except:
        return False

def compare_hsm_and_certificate(cert_path):
    # Sertifikadan genel anahtarı al
    try:
        with open(cert_path, 'rt') as cert_file:
            cert_data = cert_file.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            public_key = cert.get_pubkey()
            certificate_public_key = crypto.dump_publickey(crypto.FILETYPE_ASN1, public_key)
            encoded_certificate_public_key = base64.b64encode(certificate_public_key).decode('ascii')

            certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
            end_time = certificate.get_notAfter().decode()
            end_date_obj = datetime.strptime(end_time, "%Y%m%d%H%M%SZ")
            print(end_date_obj)
        return encoded_certificate_public_key
    except:
        return False


def Public_Key(SlotID, Slot_PIN, KeyName):
    try:
        pkcs11_lib_path = os.environ.get('PYKCS11LIB')  # HSM'nizin kütüphane yolunu değiştirin
                # PKCS11 modülünü yükle
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
        slot = pkcs11.getSlotList(tokenPresent=True)[SlotID]
        Slot_List = pkcs11.getSlotList(tokenPresent=True)
        token = pkcs11.getTokenInfo(slot)
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)

        session.login(Slot_PIN)
        key_handles = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_RSA), (CKA_LABEL, KeyName)])[0]
        attributes = session.getAttributeValue(key_handles, [CKA_MODULUS])[0]
        modulus_bytes = bytes(attributes)
        public_key = base64.b64encode(modulus_bytes).decode('ascii')
        session.logout()
        session.closeSession()
        return public_key[:-2]
    except:
        return False




def verify_certificate(CRT_Name, SlotID, Slot_PIN, KeyName):
    certificate_path = '/app/CRT/'+str(CRT_Name)
    CRT_Data = compare_hsm_and_certificate(certificate_path)
    Public_data = Public_Key(SlotID, Slot_PIN, KeyName)
    if CRT_Data == False:
        print("CRT_Data data not available")
        message = "CRT_Data data not available"
    elif Public_data == False:
        print("Public data not available")
        message = "Public data not available"
    else:
        if Public_data in CRT_Data:
            print("Certificate Valid")
            CertData_clock = Certificate_Date(certificate_path)
            now = datetime.now()
            formatted_date_time = now.strftime("%Y-%m-%d %H:%M:%S")
            if now < CertData_clock:
                message = f'Certificate valid until {CertData_clock}'
                print(message)
            else:
                message = f'Certificate expired on {CertData_clock}.'
                print(message)
        else:
            print("Certificate Invalid")
            message = "Certificate Invalid"
    return message
    



# CRTName = 'Client.crt'
# SlotID = 1
# Slot_PIN = "1111"
# KeyName = "ClientRSApub"
# verify_certificate(CRTName, SlotID, Slot_PIN, KeyName)