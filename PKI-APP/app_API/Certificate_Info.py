from PyKCS11 import *
import os
import base64
import OpenSSL.crypto
from datetime import datetime
import json

def Cert_Info(slot_id,Slot_pin):
    # HSM PKCS#11 kütüphanesinin yolunu belirtin
    pkcs11_lib_path = os.environ.get('HSM_SO_File')  # HSM'nizin kütüphane yolunu değiştirin
    # PKCS11 modülünü yükle
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib_path)
    # Token'ı al
    slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
    token = pkcs11.getTokenInfo(slot)
    print(token.label)
    # Oturumu aç (örneğin, 1111 şifresi ile)
    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
   # session.login(Slot_pin)  # HSM'ye özgü PIN'i belirtin
    # JSON verisi için boş bir liste oluşturun
    json_date = []
    # Sertifikaları listele
    certificates = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
    for certificate in certificates:
        cert_der = session.getAttributeValue(certificate, [CKA_VALUE])[0]  # DER formatında sertifika değerini alın
        cert_Name = session.getAttributeValue(certificate, [CKA_LABEL])[0]

        cert_der_bytes = bytes(cert_der)
        #print(cert_der)
        cert_pem = '-----BEGIN CERTIFICATE-----\n'
        cert_pem += base64.b64encode(cert_der_bytes).decode('ascii')
        cert_pem += '\n-----END CERTIFICATE-----'
        # Sertifika verisini yükleyin
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)

        # Sertifika sahibinin adını alın
        subject = certificate.get_subject()
        common_name = subject.CN
        country = subject.C

        # Son geçerlilik tarihini alın
        end_time = certificate.get_notAfter().decode()

        # Yayınlama tarihini alın
        start_time = certificate.get_notBefore().decode()
        # Verilen formattaki tarihi datetime nesnesine çevirin
        end_date_obj = datetime.strptime(end_time, "%Y%m%d%H%M%SZ")
        # İnsan tarafından okunabilir bir tarih formatına çevirin
        Date_End = end_date_obj.strftime("%d/%m/%Y %H:%M:%S")
        # Verilen formattaki tarihi datetime nesnesine çevirin
        start_date_obj = datetime.strptime(start_time, "%Y%m%d%H%M%SZ")
        # İnsan tarafından okunabilir bir tarih formatına çevirin
        Date_Start = start_date_obj.strftime("%d/%m/%Y %H:%M:%S")
        # Bilgileri yazdırın
        label_str = token.label
        Token_Label = label_str.replace(" ", "")
        Json_single_date = {"Slot_ID": slot_id, "Slot_Label": Token_Label, "Certificate_Name": cert_Name,"Common_Name": common_name,"Country": country ,"Last_Date": Date_End , "First_Date": Date_Start }
        json_date.append(Json_single_date)
        print(type(json_date))
        
    # Oturumu kapatın
    #session.logout()
    #session.closeSession()
    return json_date

# slot_id = 0
# Slot_pin = "1111"
# Cert_Info(slot_id,Slot_pin)