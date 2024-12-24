from PyKCS11 import *
import base64
import os


def CrtGet_obje(Slot_ID,pin,ca_cert_label):
    # lib = os.environ.get('HSM_SO_File')  # HSM kütüphanesinin yolunu güncelleyin
    # pkcs11 = PyKCS11Lib()
    # pkcs11.load(lib)
    # slot = pkcs11.getSlotList()[Slot_ID]  # HSM cihazının yuvasını seçin
    # session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)  # Oturum açın
    # session.login(pin)
    #     # CA sertifikasının etiketini belirtin
    # ca_cert = session.findObjects([
    #     (CKA_LABEL, ca_cert_label),
    #     (CKA_CLASS, CKO_CERTIFICATE)
    # ])[0]
    # cert_der = session.getAttributeValue(ca_cert, [CKA_VALUE])[0]  # DER formatında sertifika değerini alın
    # cert_der_bytes = bytes(cert_der)
    #     #print(cert_der)
    # cert_pem = '-----BEGIN CERTIFICATE-----\n'
    # cert_pem += base64.b64encode(cert_der_bytes).decode('ascii')
    # cert_pem += '\n-----END CERTIFICATE-----'
    # session.logout()
    # return cert_pem
    try:
        lib = os.environ.get('HSM_SO_File')  # HSM kütüphanesinin yolunu güncelleyin
        pkcs11 = PyKCS11Lib()
        pkcs11.load(lib)
        slot = pkcs11.getSlotList()[Slot_ID]  # HSM cihazının yuvasını seçin
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)  # Oturum açın
        session.login(pin)
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
        session.logout()
        return cert_pem
       # return full_file_path
    except:
        return False
# Slot_ID = 1
# ca_cert_label = 'ClientCert'
# a = CrtExport(Slot_ID,ca_cert_label)
# print(a)
# slot = 1
# pin = "1111"
# CRT_Name = "ProcenneCRT"
# CRT_Obje = CrtGet_obje(slot,pin,CRT_Name)
# print(CRT_Obje)