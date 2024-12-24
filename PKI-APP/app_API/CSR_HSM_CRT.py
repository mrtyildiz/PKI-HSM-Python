from PyKCS11 import *
from OpenSSL import crypto
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
#from Get_Private_Key import Private_Key
from File_Read import Read_File_Func
from CA_Export import CrtExport
import os
import base64

from Get_Private_Key import Private_Key

def HSM_CSR(Slot,Slot_PIN,KeyName,csr_fileName,ca_cert_label,Days_int):
    try:
        private_key = Private_Key(Slot,Slot_PIN,KeyName)
        print(private_key)
        TypeCSR = "uploads"
        csr_data = Read_File_Func(TypeCSR,csr_fileName)
        lib = os.environ.get('HSM_SO_File')  # HSM kütüphanesinin yolunu güncelleyin
        pkcs11 = PyKCS11Lib()
        pkcs11.load(lib)
        slot = pkcs11.getSlotList()[Slot]  # HSM cihazının yuvasını seçin
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)  # Oturum açın
            # CA sertifikasının etiketini belirtin
        ca_cert = session.findObjects([
            (CKA_LABEL, ca_cert_label),
            (CKA_CLASS, CKO_CERTIFICATE)
        ])[0]
        cert_der = session.getAttributeValue(ca_cert, [CKA_VALUE])[0]  # DER formatında sertifika değerini alın
        cert_der_bytes = bytes(cert_der)
        #print(cert_der)
        cert_pem = '-----BEGIN CERTIFICATE-----\n'
        cert_pem += base64.b64encode(cert_der_bytes).decode('ascii')
        cert_pem += '\n-----END CERTIFICATE-----'

        ca_certificate = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        csr = x509.load_pem_x509_csr(csr_data.encode(), default_backend())
        current_utc_time = datetime.utcnow()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(current_utc_time)
            .not_valid_after(current_utc_time + timedelta(days=Days_int))
            .sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
        )
        crt_data = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        CSR_Array = csr_fileName.split(".")
        CRT_Out_file = CSR_Array[0]+".crt"
        Root_DIR_CRT= "/app/CRT/"
        crt_file = Root_DIR_CRT+str(CRT_Out_file)
        #output_file = 'certificate.pem'  # Çıktı sertifikasının yolunu belirtin
        crt_decode = crt_data.decode()
        print(crt_decode)
        with open(crt_file, 'w') as f:
            f.write(crt_decode)
        result = "Certificate generated"
        #result = crt_decode
    except:
        result = "Certificate creation error"
        #result = crt_decode
    return result


# Slot = 0
# Slot_PIN = "1111"
# KeyName = "Clientpriv"
# csr_fileName = "HiyTech.csr"
# ca_cert_label = "CACRT"
# a = HSM_CSR(Slot,Slot_PIN,KeyName,csr_fileName,ca_cert_label)