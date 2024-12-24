from PyKCS11 import *
from PyKCS11.LowLevel import *
import os
import time
def AESKeysRemove(slot,pin,Obje_Label):
    try:
        pkcs11_lib_path = os.environ.get('HSM_SO_File')
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
        slot = pkcs11.getSlotList(tokenPresent=True)[slot]
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(pin)
        Obje = session.findObjects([(CKA_CLASS, CKO_SECRET_KEY),(CKA_LABEL, Obje_Label)])[0]
        session.destroyObject(Obje)

        session.logout()
        session.closeSession()
        result = "Object deletion successful"
        return result
    except Exception as e:
        print(e)
        return e

def RrivateKeysRemove(slot_id,slot_pin,Obje_Label):
    try:
        pkcs11_lib_path = os.environ.get('HSM_SO_File')
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
        slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(slot_pin)
        Obje = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),(CKA_LABEL, Obje_Label)])[0]
        session.destroyObject(Obje)
        session.logout()
        session.closeSession()
        result = "Object deletion successful"
    except Exception as e:
        print(e)
        result = "Object not found"
    return result

def Certificate(slot_id,slot_pin,Obje_Label):
    try:
        pkcs11_lib_path = os.environ.get('HSM_SO_File')
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
        slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        certificates = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),(CKA_LABEL, Obje_Label)])[0]
        session.destroyObject(certificates)
        result = "Object deletion successful"
    except Exception as e:
        print(e)
        result = "Object not found"
    return result
def RemoveObje(slot_id,slot_pin,ObjeType,Obje_Label):
    try:
        if ObjeType == "Certificate":
            result = Certificate(slot_id,slot_pin,Obje_Label)

        elif ObjeType == "Private":
            result = RrivateKeysRemove(slot_id,slot_pin,Obje_Label)
        elif ObjeType == "Public":
            try:
                pkcs11_lib_path = os.environ.get('HSM_SO_File')
                pkcs11 = PyKCS11Lib()
                pkcs11.load(pkcs11_lib_path)
                slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
                session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
                session.login(slot_pin)
                Obje = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY),(CKA_LABEL, Obje_Label)])[0]
                session.destroyObject(Obje)
                session.logout()
                session.closeSession()
                result = "Object deletion successful"
            except Exception as e:
                print(e)
                result = "Object not found"
        elif ObjeType == "User":
            try:
                pkcs11_lib_path = os.environ.get('HSM_SO_File')
                pkcs11 = PyKCS11Lib()
                pkcs11.load(pkcs11_lib_path)
                slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
                session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
                Obje = session.findObjects([(CKA_CLASS, CKO_DATA),(CKA_LABEL, Obje_Label)])[0]
                session.destroyObject(Obje)
                result = "Object deletion successful"
            except:
                result = "Object not found"
        elif ObjeType == "Simetrik":
            result = AESKeysRemove(slot_id,slot_pin,Obje_Label)
            return result
        else:
            try:
                pkcs11_lib_path = os.environ.get('HSM_SO_File')
                pkcs11 = PyKCS11Lib()
                pkcs11.load(pkcs11_lib_path)
                slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
                session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
                session.login(slot_pin)
                Obje = session.findObjects([(CKA_LABEL, Obje_Label)])[0]
                session.destroyObject(Obje)
                result = "Object deletion successful"
                session.logout()
                session.closeSession()
            except:
                result = "Object not found"
        return result
    except Exception as e:
        print(e)
        result = "Object deletion successful"
        return result
