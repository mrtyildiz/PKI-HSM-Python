from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex
import os
HSM_SO_File = os.environ.get('PYKCS11LIB')

# cleartext = b'murat'
# init_vector = os.urandom(16)
# iv_str = init_vector.hex()
# print(iv_str)
def AESEncrypt(ID,PIN,KeyName,Data,init_Vector_str):
    try:
        Bytes_Data = Data.encode('utf-8')
        iv_bytes = bytes.fromhex(init_Vector_str) 
        with HsmClient(slot=ID, pin=PIN, pkcs11_lib=HSM_SO_File) as c:
            handles = c.get_object_handle(label=KeyName)
            ciphertext = c.encrypt(handle=handles,
                                data=Bytes_Data,
                                mechanism=HsmMech.AES_CBC_PAD,
                                iv=iv_bytes)
            encrypt_data = bytes_to_hex(ciphertext)
        result = {"Encrypt Data: " : encrypt_data}
    except:
        error = "HSM is error"
        result = {"Error: " : error}
    return result


# ID = 0
# PIN = "1111"
# KeyName = "AESKeys"
# Data = "3f04ca482dce87121fc8f9f43ef97d08"
# init_Vector_str = "4b04ae274cc4181cb2ee8ca9cdbb11d3"
# AESEncrypt(SlotID,SlotPIN,KeyName,Data,init_Vector_str)

def AESDEcryption(ID,PIN,KeyName,Data,init_Vector_str):
    try:
        with HsmClient(slot=ID, pin=PIN, pkcs11_lib=HSM_SO_File) as c:
            handles = c.get_object_handle(label=KeyName)
            init_vector = bytes.fromhex(init_Vector_str)
            byte_data = bytes.fromhex(Data)
            cleartext = c.decrypt(handle=handles, data=byte_data, mechanism=HsmMech.AES_CBC_PAD, iv=init_vector)

            Decrypt_Data = cleartext.decode('utf-8')
        result = {"Decrypt Data: " : Decrypt_Data}
    except:
        error = "HSM is error"
        result = {"Error: " : error}
    return result

# ID = 0
# PIN = "1111"
# KeyName = "AESKeys"
# Data = "5c7eb67b20c68857fc3b13621b1726c5"
# init_Vector_str = "4b04ae274cc4181cb2ee8ca9cdbb11d3"
# a = AESDEcryption(ID,PIN,KeyName,Data,init_Vector_str)
# print(a)