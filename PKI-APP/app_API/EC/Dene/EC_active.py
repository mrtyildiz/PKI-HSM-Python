
from PyKCS11 import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load()
slot = pkcs11.getSlotList(tokenPresent=True)[1]
session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("1111")

# Private Key'ı bulma ve yükleme
private_key_label = "ECKeys"
private_key = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, private_key_label)])[0]

# Public Key'ı bulma ve yükleme
public_key_label = "ECKeys"
public_key = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_LABEL, public_key_label)])[0]

# ECDSA Sign işlemi
data_to_sign = b"Hello, World!"
signature = session.sign(private_key, data_to_sign, Mechanism(CKM_ECDSA))
print(signature)
# ECDSA Verify işlemi
is_verified = session.verify(public_key, data_to_sign, signature, Mechanism(CKM_ECDSA))
print(is_verified)
# ECDH Encrypt ve Decrypt işlemleri
# Public Key'ın raw değerini al


