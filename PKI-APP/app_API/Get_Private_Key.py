from PyKCS11 import *
from OpenSSL import crypto
import os
from cryptography.hazmat.primitives.asymmetric import rsa

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
# slot_id = 0
# pin = "1111"
# CA_Key = "CAKeypriv"
# a = Private_Key(slot_id,pin,CA_Key)
# print(a)