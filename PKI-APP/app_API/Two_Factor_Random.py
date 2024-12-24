from pyhsm.hsmclient import HsmClient
from pyhsm.convert import bytes_to_hex
import os
import binascii
HSM_SO_File = os.environ.get('PYKCS11LIB')


def RandomCharacter(ID,PIN,Character):
    # with HsmClient(slot=ID, pin=PIN, pkcs11_lib=HSM_SO_File) as c:
    #     rnd_bytes = c.generate_random(size=Character)
    #     hex_string = bytes_to_hex(rnd_bytes)
    #     Code = hex_string[0:Character]
    #     print(Code)
    try:
        with HsmClient(slot=ID, pin=PIN, pkcs11_lib=HSM_SO_File) as c:
            rnd_bytes = c.generate_random(size=Character)
            hex_string = bytes_to_hex(rnd_bytes)
            Code = hex_string[0:Character]
            print(Code)
        message = {"Produced Code: " : Code}
    except:
        message = {"Generated Code Error"}
    return message
# Slot_ID = 0
# Slot_PIN = "1111"
# Character = 6
# RandomCharacter(Slot_ID,Slot_PIN,Character)