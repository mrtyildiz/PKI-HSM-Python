from ctypes import CDLL, c_void_p
from ctypes import *
import sys

import PyKCS11
from PyKCS11 import *
from PyKCS11.LowLevel import *
import os
p11 = None

def die(message):
    print(message)
    if p11:
        p11.C_Finalize(0)
    sys.exit(1)

CK_PDS_CONFIG_HW_CRYPTO_DISABLED = 0x80000001
CK_PDS_CONFIG_EXPERIMENTAL_FEATURES_ENABLED = 0x80000002

class Configuration(Structure):
    _fields_ = [
        ("type", c_ulong),
        ("value_ptr", c_void_p),
        ("value_len", c_ulong),
    ]

def load_module(path):
    global p11

    p11 = CDLL(path)

    # Assuming the function names are different or have a different convention
    p11.C_Initialize.argtypes = [c_void_p]
    p11.C_Initialize.restype = c_ulong

    p11.C_Finalize.argtypes = [c_void_p]
    p11.C_Finalize.restype = c_ulong

    p11.API_FW_login.argtypes = [c_int, c_char_p, c_uint]
    p11.API_FW_login.restype = c_int

    p11.C_PDS_SetConfigurationValue.argtypes = [c_char_p, c_ulong,
                                                POINTER(Configuration),
                                                c_ulong]
    p11.C_PDS_SetConfigurationValue.restype = c_ulong

def cast_to_void_p(value):
    return cast(pointer(value), c_void_p)

def Token_Create(ho_pin,ha_pin,Token_Label,SO_PIN,User_PIN):
    try:
        module_path = "/lib64/libprocryptoki.so"
        name = "hw_crypto_disabled"
        value = "True"

        config_types = {
            "hw_crypto_disabled": CK_PDS_CONFIG_HW_CRYPTO_DISABLED,
            "experimental_features_enabled": CK_PDS_CONFIG_EXPERIMENTAL_FEATURES_ENABLED,
        }

        if name not in config_types:
            names = " ".join(config_types.keys())
            die("Name must be one of these: {}".format(names))

        load_module(module_path)

        rv = p11.C_Initialize(c_void_p(0))
        if rv:
            die("C_Initialize failed. rv={}".format(rv))

        rv = p11.API_FW_login(1, bytes(ho_pin, "utf8"), len(ho_pin))
        if rv:
            die("API_FW_login failed. rv={}".format(rv))

        value = c_char(1) if eval(value) else c_char(0)

        config = Configuration(config_types[name], cast_to_void_p(value), c_ulong(sizeof(value)))

        rv = p11.C_PDS_SetConfigurationValue(bytes(ha_pin, "utf8"), len(ha_pin), byref(config), c_ulong(1))
        if rv:
            die("C_PDS_SetConfigurationValue failed. rv={}".format(rv))

        p11.C_Finalize(0)
    except:
        result_Err = "HSM login Faild"
        return result_Err
    else:
        pkcs11_lib_path = os.environ.get('HSM_SO_File')
        pkcs11 = PyKCS11Lib()
        pkcs11.load(pkcs11_lib_path)
        slots = pkcs11.getSlotList(tokenPresent=True)
        # Belirli bir slot üzerinde yeni bir token oluştur
        print(slots)
        slot_id = int(len(slots))-1
        new_token_label = f'{Token_Label}'+' '*32
        pkcs11.initToken(slot_id, SO_PIN, new_token_label)
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load()
        slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
        session = pkcs11.openSession(slot, PyKCS11.CKF_RW_SESSION)
        session.login(SO_PIN, PyKCS11.CKU_SO)
        session.initPin(User_PIN)
        session.logout()
        session.closeSession()
        result_True = "Token is created" # Thank you Mert
        return result_True

# ho_pin = "1111"
# ha_pin = "1111"
# Token_Label = "Token_Name"
# SO_PIN = "1111"
# User_PIN = "1111"
# a = Token_Create(ho_pin,ha_pin,Token_Label,SO_PIN,User_PIN)
# print(a)