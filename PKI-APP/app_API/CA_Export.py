from PyKCS11 import *
import base64
import os


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
# Slot_ID = 0
# ca_cert_label = 'CACertificatesss'
# a = CrtExport(Slot_ID,ca_cert_label)
# print(a)