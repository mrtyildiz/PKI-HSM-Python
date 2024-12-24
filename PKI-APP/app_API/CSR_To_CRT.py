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
def Private_Key(slot,pin,CA_KeyName):
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

def csr_t_crt(slot,pin,csr_fileName,CA_CRT_Name,CA_KeyName):
    private_key = Private_Key(slot,pin,CA_KeyName)
    # CSR dosyasını yükleme
    TypeCSR = "uploads"
    csr_data = Read_File_Func(TypeCSR,csr_fileName)
    # CA yükleme
    CA_File = CrtExport(slot,CA_CRT_Name)
    if CA_File:
        TypeCRT = "CRT"
        ca_data = Read_File_Func(TypeCRT,CA_CRT_Name)
        ca_certificate = x509.load_pem_x509_certificate(ca_data.encode(), default_backend())
        # CSR verisini yükleyin
        csr = x509.load_pem_x509_csr(csr_data.encode(), default_backend())
        current_utc_time = datetime.utcnow()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(current_utc_time)
            .not_valid_after(current_utc_time + timedelta(days=365))
            .sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
        )
        crt_data = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        # Sertifikayı dosyaya yazma
        CSR_Array = csr_fileName.split(".")
        CRT_Out_file = CSR_Array[0]+".crt"
        Root_DIR_CRT= "/app/CRT/"
        crt_file = Root_DIR_CRT+str(CRT_Out_file)
        #output_file = 'certificate.pem'  # Çıktı sertifikasının yolunu belirtin
        crt_decode = crt_data.decode()

        with open(crt_file, 'w') as f:
            f.write(crt_decode)
        print("Sertifika oluşturma işlemi tamamlandı.")
        return crt_decode
    else:
        return CA_File



# slot = 0
# pin = "1111"
# csr_fileName = "procenne.com.csr"
# CA_CRT_Name = "privCA"
# CA_KeyName = "CAKeypriv"
# a = csr_t_crt(slot,pin,csr_fileName,CA_CRT_Name,CA_KeyName)
# print(a)
