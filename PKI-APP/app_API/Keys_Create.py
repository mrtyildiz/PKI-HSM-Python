from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmSymKeyGen
from pyhsm.hsmclient import HsmClient
from pyhsm.convert import hex_to_bytes
from pyhsm.eccurveoids import EcCurveOids
import os
HSM_SO_File = os.environ.get('PYKCS11LIB')
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

# Slot_ID = 2
# Slot_PIN = "1111"
# AES_KeyName = "AES_Ke"
# BITS = 256
# a = AES_Creates(Slot_ID,Slot_PIN,AES_KeyName,BITS)
# print(a)