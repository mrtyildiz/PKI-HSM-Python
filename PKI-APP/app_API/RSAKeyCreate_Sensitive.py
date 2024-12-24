from PyKCS11 import PyKCS11
import os
# PKCS#11 modülünü yükleyin
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11_lib_path = os.environ.get('HSM_SO_File')
pkcs11.load(pkcs11_lib_path)

# Slot ve oturumu açın
slot = pkcs11.getSlotList()[0]
session = pkcs11.openSession(slot, PyKCS11.CKF_RW_SESSION)
session.login('1111')

# Anahtar oluşturma parametrelerini ayarlayın
mechanism = pkcs11.findMechanism(KEY_GEN_MECHANISM)
public_key_attributes = [
    (MODULUS_BITS, 2048),
    (PUBLIC_EXPONENT, [0x01, 0x00, 0x01]),  # RSA F4 public exponent
]

private_key_attributes = [
    (TOKEN, True),  # Anahtarın HSM'de saklanacağını belirtiyoruz
]

# Anahtar çiftini oluşturun
public_key, private_key = session.generateKeyPair(mechanism, public_key_attributes, private_key_attributes)

# Anahtarları kullanabilirsiniz
print("Public Key:", public_key)
print("Private Key:", private_key)

# Oturumu kapatın
session.logout()
session.closeSession()
