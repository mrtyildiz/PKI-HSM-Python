from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.x509 import Name, CertificateBuilder
from cryptography import x509
import datetime
import base64
import os
import json
import OpenSSL.crypto
import cryptography.x509 as x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from OpenSSL import crypto

from datetime import datetime, timedelta  # Import the datetime module

from cryptography.hazmat.backends import default_backend


def Certificate_Load(ID,PIN,CerFile,CerName):
    SlotID = ID
    SlotPIN = PIN
    CRT_ROOT_DIR = "/app/CRT/"
    CertificateFile = str(CRT_ROOT_DIR)+CerFile
    
    CertificateName = CerName
    pkcs11_lib = os.environ.get('PYKCS11LIB')
    #print(pkcs11_lib)
    Load_Certificate = 'pkcs11-tool --module '+str(pkcs11_lib)+' --slot '+str(SlotID)+' --login --pin '+str(SlotPIN)+' --write-object '+str(CertificateFile)+' --type cert --label "'+str(CertificateName)+'"'
    os.system(Load_Certificate)
    return True

def Cert_Info(slot_id,Slot_pin):
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
    session.login(Slot_pin)  # HSM'ye özgü PIN'i belirtin
    # JSON verisi için boş bir liste oluşturun
    json_date = []
    # Sertifikaları listele
    certificates = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
    for certificate in certificates:
        cert_der = session.getAttributeValue(certificate, [CKA_VALUE])[0]  # DER formatında sertifika değerini alın
        cert_Name = session.getAttributeValue(certificate, [CKA_LABEL])[0]

        cert_der_bytes = bytes(cert_der)
        ##print(cert_der)
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
        
    # Oturumu kapatın
    session.logout()
    session.closeSession()
    return json_date


def Cert_InfoSing(slot_id,Slot_pin,Certifcate_Name):
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
    session.login(Slot_pin)  # HSM'ye özgü PIN'i belirtin
    # JSON verisi için boş bir liste oluşturun
    json_date = []
    # Sertifikaları listele
    certificates = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
    for certificate in certificates:
        cert_der = session.getAttributeValue(certificate, [CKA_VALUE])[0]  # DER formatında sertifika değerini alın
        cert_Name = session.getAttributeValue(certificate, [CKA_LABEL])[0]

        cert_der_bytes = bytes(cert_der)
        ##print(cert_der)
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
        #print("Common Name (CN):", common_name)
        #print("Country (C):", country)
        #print("Son Geçerlilik Tarihi:", Date_End)
        #print("Başlangıç Tarihi:", Date_Start)
        if cert_Name == Certifcate_Name:
            Json_single_date = {"Certificate_Name": cert_Name,"Common_Name": common_name,"Country": country ,"Last_Date": Date_End , "First_Date": Date_Start }
            json_date.append(Json_single_date)
        else:
            pass
        
    # Oturumu kapatın
    session.logout()
    session.closeSession()
    return json_date



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
        #print("İstemci sertifikası doğrulanamadı:", e)
        result = False
    # Oturumu kapatın
    session.logout()
    session.closeSession()
    return result




def Private_Key(slot,pin,CA_KeyName):
    try:
        pkcs11_lib = os.environ.get('HSM_SO_File')   # HSM PKCS#11 kütüphanesinin yolu
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib)
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(pin)
        private_key = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),
                                                (CKA_LABEL, CA_KeyName)])[0]
            # Modulus ve public exponent değerlerini alın
        modulus = session.getAttributeValue(private_key, [CKA_MODULUS])[0]
        public_exponent = session.getAttributeValue(private_key, [CKA_PUBLIC_EXPONENT])[0]
        # RSA anahtarını oluşturun
        private_numbers = rsa.RSAPrivateNumbers(
            p=int.from_bytes(session.getAttributeValue(private_key, [CKA_PRIME_1])[0], byteorder="big"),
            q=int.from_bytes(session.getAttributeValue(private_key, [CKA_PRIME_2])[0], byteorder="big"),
            d=int.from_bytes(session.getAttributeValue(private_key, [CKA_PRIVATE_EXPONENT])[0], byteorder="big"),
            dmp1=int.from_bytes(session.getAttributeValue(private_key, [CKA_EXPONENT_1])[0], byteorder="big"),
            dmq1=int.from_bytes(session.getAttributeValue(private_key, [CKA_EXPONENT_2])[0], byteorder="big"),
            iqmp=int.from_bytes(session.getAttributeValue(private_key, [CKA_COEFFICIENT])[0], byteorder="big"),
            public_numbers=rsa.RSAPublicNumbers(
                e=int.from_bytes(public_exponent, byteorder="big"),
                n=int.from_bytes(modulus, byteorder="big")))
        private_key = private_numbers.private_key()
        # HSM cihazından çıkış yapma
        session.logout()
        return private_key
    except:
        return False


  # Import the datetime module
def Array_Create(array):
    if os.path.exists(array):
        pass
    else:
        os.mkdir(array)

def CSR_Create_New(slot,pin,KeyName,Company,Json_Data):
    Data = Json_Data.split('#')
    name_attributes = []
    # Remove the last element from the list
    Data.pop()

    name_attributes = []

    for item in Data:
        try:
            name_attribute = eval(item)
            name_attributes.append(name_attribute)
            subject_attributes = [eval(attribute_str) for attribute_str in Data]    
            ROOT_DIR_CSR = "/app/CSR"
            if os.path.exists(ROOT_DIR_CSR):
                pass
            else:
                os.mkdir(ROOT_DIR_CSR)
            os.chdir(ROOT_DIR_CSR)
            
            #Private Keyin Çekilmesi 
            private_key = Private_Key(slot,pin,KeyName)
            if private_key == False:
                result = "Key Not Found"
            else:
                # CSR altında kullanılacak konu bilgilerini oluşturun
                subject = x509.Name(subject_attributes)

                # Create the CSR with validity period
            
                # # CSR oluşturun
                csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
                    private_key, hashes.SHA256()
                )
                CSR_Files = Company+".csr"

                # CSR'i bir dosyaya yazın (örneğin, csr.pem)
                with open(CSR_Files, "wb") as csr_file:
                    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
                    csr_file.write(csr_pem)
                result = str(ROOT_DIR_CSR) +"/"+ str(CSR_Files)
                #result2 = "/app"+str(result)
            return result
        except Exception as e:
            result = f"Error:{str(e)}"
            #print(result)
            return result
