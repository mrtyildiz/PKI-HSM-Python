import os
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

def read_key_from_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def encrypt(text):
    key_file_path = "/app/Keys/keySlot"
    key = read_key_from_file(key_file_path)
    key = key.ljust(32)[:32]  # Ensure key length is 32 bytes
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_text = text.ljust(16 * (len(text) // 16 + 1)).encode('utf-8')  # Pad the text to be a multiple of 16 bytes
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    return b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext):
    key_file_path = "/app/Keys/keySlot"
    key = read_key_from_file(key_file_path)
    key = key.ljust(32)[:32]  # Ensure key length is 32 bytes
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ciphertext_bytes = b64decode(ciphertext)
    padded_text = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    return padded_text.decode('utf-8').rstrip()

import os
HSM_SO_File = os.environ.get('PYKCS11LIB')

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


def AESDEcryption(ID,PIN,KeyName,Data,init_Vector_str):
    try:
        with HsmClient(slot=ID, pin=PIN, pkcs11_lib=HSM_SO_File) as c:
            handles = c.get_object_handle(label=KeyName)
            init_vector = bytes.fromhex(init_Vector_str)
            byte_data = bytes.fromhex(Data)
            cleartext = c.decrypt(handle=handles, data=byte_data, mechanism=HsmMech.AES_CBC_PAD, iv=init_vector)
            Decrypt_Data = cleartext.decode('utf-8')
        result = {"Decrypt Data: " : Decrypt_Data}
    except Exception as e:
        print(e)
        error = "HSM is error"
        result = {"Error: " : error}
    return result


def Slot_Find(API_Key,Action,Slot_PIN):
    Real_API_Key = os.environ.get('API_Slot')
    Use_PIN = os.environ.get('API_Slot')
    Slot_PIN_Main = os.environ.get('Slot_PIN')

    if API_Key == Real_API_Key:
        if Action == "Encrypt":
            Slot_ID = int(os.environ.get('Slot_ID'))
            PIN = decrypt(Slot_PIN_Main)
            Key_Name = os.environ.get('Slot_Key_Name')
            init_vec = "8d9d3c2f778c0b6c0af32e24c5b1834b"
            result = AESEncrypt(Slot_ID,PIN,Key_Name,Slot_PIN,init_vec)
            return result
        elif Action == "Decrypt":
            Slot_ID = int(os.environ.get('Slot_ID'))
            PIN = decrypt(Slot_PIN_Main)
            Key_Name = os.environ.get('Slot_Key_Name')
            init_vec = "8d9d3c2f778c0b6c0af32e24c5b1834b"
            result = AESDEcryption(Slot_ID,PIN,Key_Name,Slot_PIN,init_vec)
            return result
        else:
            message = "process could not be identified"
    else:
        message = "Worng API"
    return message