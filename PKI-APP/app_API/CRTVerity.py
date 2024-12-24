import cryptography.x509 as x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import os
from PyKCS11 import *
import base64
import OpenSSL.crypto
from OpenSSL import crypto
from datetime import datetime

def VeriftyCRT(slot_id,slot_pin,CA_CRT_Name,CRT_Name):
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
    session.login(slot_pin)  # HSM'ye özgü PIN'i belirtin
    certificates = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),(CKA_LABEL, CA_CRT_Name)])
    ### Sertifika dosyası elde edildi ###
    if len(certificates) == 0:
        result = "CA Certificate Not Found"
        return result
    else:
        for certificate in certificates:
            cert_value = session.getAttributeValue(certificate, [CKA_VALUE])[0]
            cert_value_bytes = bytes(cert_value)
            cert_pem = '-----BEGIN CERTIFICATE-----\n'
            cert_pem += base64.b64encode(cert_value_bytes).decode('ascii')
            cert_pem += '\n-----END CERTIFICATE-----'
            CA_certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)

    CRT_DIR = "/app/CRT/"
    CRT_PATH = str(CRT_DIR)+str(CRT_Name)
    with open(CRT_PATH, 'r') as f:
        crt_data = f.read()
        
    Client_certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, crt_data)
    end_time = Client_certificate.get_notAfter().decode()
    end_date_obj = datetime.strptime(end_time, "%Y%m%d%H%M%SZ")
    # CA sertifikasını kullanarak istemci sertifikasını doğrulama
    store = crypto.X509Store()
    store.add_cert(CA_certificate)
    store_ctx = crypto.X509StoreContext(store, Client_certificate)
    try:
        store_ctx.verify_certificate()
        now = datetime.now()
        formatted_date_time = now.strftime("%Y-%m-%d %H:%M:%S")
        if now < end_date_obj:
            return True
        else:
            return False
    except crypto.X509StoreContextError as e:
        print("İstemci sertifikası doğrulanamadı:", e)
        result = False
    # Oturumu kapatın
    session.logout()
    session.closeSession()
    return result
# Slot = 0
# Slot_pin = "1111"
# CA_CRT_Name = "CAKeypriv"
# CRT_Name = "HiyTech.crt"
# VeriftyCRT(Slot,Slot_pin,CA_CRT_Name,CRT_Name)
