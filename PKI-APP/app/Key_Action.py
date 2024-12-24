from PyKCS11 import *
from asn1crypto.keys import ECDomainParameters, NamedCurve
from pyhsm.hsmclient import HsmClient
import os
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmSymKeyGen
from pyhsm.hsmclient import HsmClient
from pyhsm.convert import hex_to_bytes
from pyhsm.eccurveoids import EcCurveOids

HSM_SO_File = os.environ.get('PYKCS11LIB')
def EC_Create(Slot_ID,Slot_PIN,label,Algoritma):
    try:
        S_PIN = int(Slot_PIN)
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load()

        slot = pkcs11.getSlotList(tokenPresent=True)[Slot_ID]

        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(Slot_PIN)

        key_id = (0x22,)

        Algoritma = 'ansiX9p192r1'
        if Algoritma == 'ansiX9p192r1':
            curve = "1.2.840.10045.3.1.1"
        elif Algoritma == 'ansiX9p256r1':
            curve = "1.2.840.10045.3.1.7"
        elif Algoritma == 'ansiX9p384r1':
            curve = "1.3.132.0.34"
        elif Algoritma == 'brainpoolP192r1':
            curve = "1.3.36.3.3.2.8.1.1.1"
        elif Algoritma == 'brainpoolP224r1':
            curve = "1.3.36.3.3.2.8.1.1.2"
        elif Algoritma == 'brainpoolP256r1':
            curve = "1.3.36.3.3.2.8.1.1.4"
        elif Algoritma == 'nistp192':
            curve = "1.2.840.10045.3.1.1"
        elif Algoritma == 'nistp224':
            curve = "1.3.132.0.33"
        elif Algoritma == 'nistp521':
            curve = "1.3.132.0.35"
        elif Algoritma == 'prime192v1':
            curve = "1.2.840.10045.3.1.1"
        elif Algoritma == 'prime192v2':
            curve = "1.2.840.10045.3.1.2"
        elif Algoritma == 'prime192v3':
            curve = "1.2.840.10045.3.1.3"
        elif Algoritma == 'prime256v1':
            curve = "1.2.840.10045.3.1.7"
        elif Algoritma == 'prime384v1':
            curve = "1.3.132.0.34"
        else:
            curve = Algoritma


        # Setup the domain parameters, unicode conversion needed for the curve string
        domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
        ec_params = domain_params.dump()
        pub_key_label = label + "pub"
        priv_key_label = label + "priv"
        ec_public_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_EC_PARAMS, ec_params),
            (PyKCS11.CKA_LABEL, pub_key_label),
        ]

        ec_priv_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_LABEL, priv_key_label),
        ]

        (pub_key, priv_key) = session.generateKeyPair(
            ec_public_tmpl, ec_priv_tmpl, mecha=PyKCS11.MechanismECGENERATEKEYPAIR
        )

        session.logout()
        session.closeSession()
        result = f'Created EC Key named {label}'
    except Exception as e:
        print(f"An error occurred: {e}")
        if 'CKR_DEVICE_ERROR' in str(e):
            print("Burada")
            return True
        else:
            return False
        # result = f'{e}'
        #result = f'EC Key named {label} could not be generated'
    return result


def RSA_Create(Slot_ID,Slot_PIN,KeyName,BIT):
   HSM_SO_File = os.environ.get('PYKCS11LIB')
   try:
    with HsmClient(slot=Slot_ID, pin=Slot_PIN, pkcs11_lib=HSM_SO_File) as c:
         PubKeyName = KeyName+"pub"
         PriKeyName = KeyName+"priv"
         # BIT = 512,1024,2048,3072,4096
         key_handles = c.create_rsa_key_pair(public_key_label=PubKeyName,
                                          private_key_label=PriKeyName,
                                          key_length=BIT,
                                          public_exponent=b"\x01\x00\x01",
                                          token=True,
                                          modifiable=False,
                                          extractable=True,
                                          sign_verify=True,
                                          encrypt_decrypt=True,
                                          sensitive=False,
                                          wrap_unwrap=True,
                                          derive=False)
        #  print(dir(key_handles))
        #  print("public_handle: " + str(key_handles[0]))
        #  print("private_handle: " + str(key_handles[1]))

         # message = "RSA Key Oluşturuldu"

   except Exception as e:
        print(f"An error occurred: {e}")
        if 'CKR_DEVICE_ERROR (0x00000030)' in str(e):
            return True
        else:
            return False
   else:
      return True

def AES_Creates(ID,PIN,KeyName,BITS):
    try:
        with HsmClient(slot=ID, pin=PIN, pkcs11_lib=HSM_SO_File) as c:
            key_handle = c.create_secret_key(key_label=KeyName,
                                            key_type=HsmSymKeyGen.AES,
                                            key_size_in_bits=BITS,
                                            token=True,
                                            private=True,
                                            modifiable=False,
                                            extractable=False,
                                            sign=True,
                                            verify=True,
                                            decrypt=True,
                                            wrap=True,
                                            unwrap=True,
                                            derive=False)
    except Exception as e:
        print(f"An error occurred: {e}")
        if 'CKR_DEVICE_ERROR (0x00000030)' in str(e):
            return True
        else:
            return False
    else:
        return True
