import os
from Slot_PIN_Priv_Encrypt import *
from AES_Encrypt_Decrypt import *
from SlotPIN.SlotPINEncDec import decrypt
def Slot_Find(API_Key,Action,Slot_PIN):
    Real_API_Key = os.environ.get('API_Slot')
    Use_PIN = os.environ.get('API_Slot')
    Slot_PIN_Main = os.environ.get('Slot_PIN')
    print(Action)
    if API_Key == Real_API_Key:
        if Action == "Encrypt":
            print("Burada")
            Slot_ID = int(os.environ.get('Slot_ID'))
            PIN = decrypt(Slot_PIN_Main)
            Key_Name = os.environ.get('Slot_Key_Name')
            init_vec = "8d9d3c2f778c0b6c0af32e24c5b1834b"
            result = AESEncrypt(Slot_ID,PIN,Key_Name,Slot_PIN,init_vec)
            return result
        elif Action == "Decrypt":
            Slot_ID = int(os.environ.get('Slot_ID'))
            print(decrypt(Slot_PIN_Main))
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