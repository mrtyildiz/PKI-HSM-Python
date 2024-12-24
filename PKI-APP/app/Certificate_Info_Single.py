from PyKCS11 import *
import os
import base64
import OpenSSL.crypto
from datetime import datetime
import json

def Cert_InfoSing(slot_id,Slot_pin,Certifcate_Name):
    pkcs11_lib_path = os.environ.get('HSM_SO_File')
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib_path)
    slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
    session = pkcs11.openSession(slot)
    json_date = []
    certificate = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),(CKA_LABEL, Certifcate_Name)])[0]
    cert_der = session.getAttributeValue(certificate, [CKA_VALUE])[0]
    cert_Name = session.getAttributeValue(certificate, [CKA_LABEL])[0]
    cert_der_bytes = bytes(cert_der)
    cert_pem = '-----BEGIN CERTIFICATE-----\n'
    cert_pem += base64.b64encode(cert_der_bytes).decode('ascii')
    cert_pem += '\n-----END CERTIFICATE-----'
    certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
    subject = certificate.get_subject()
    common_name = subject.CN
    country = subject.C
    end_time = certificate.get_notAfter().decode()
    start_time = certificate.get_notBefore().decode()
    end_date_obj = datetime.strptime(end_time, "%Y%m%d%H%M%SZ")
    Date_End = end_date_obj.strftime("%d/%m/%Y %H:%M:%S")
    start_date_obj = datetime.strptime(start_time, "%Y%m%d%H%M%SZ")
    Date_Start = start_date_obj.strftime("%d/%m/%Y %H:%M:%S")
    Json_single_date = {"Certificate_Name": cert_Name,"Common_Name": common_name,"Country": country ,"Last_Date": Date_End , "First_Date": Date_Start }
    json_date.append(Json_single_date)
    return json_date