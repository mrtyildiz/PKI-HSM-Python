from PyKCS11 import *
from PyKCS11.LowLevel import *
import os
def Slot_Label_Func():
    try:
        pkcs11_lib_path = os.environ.get('HSM_SO_File')
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
        slots = pkcs11.getSlotList(tokenPresent=True)
        Slot_Label_Array =[]
        for i in range(len(slots)-1):
            info = pkcs11.getTokenInfo(slots[i])
            Label = info.label
            Token_Label = "".join(Label.split())
            Slot_Label_Array.append(Token_Label)
        
        return Slot_Label_Array
    except:
        result = "Failed to connect to HSM device"
        return result