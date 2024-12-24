from __future__ import print_function
import PyKCS11
from PyKCS11 import *
from PyKCS11.LowLevel import *
import os

pkcs11_lib_path = os.environ.get('HSM_SO_File')
pkcs11 = PyKCS11Lib()
pkcs11.load(pkcs11_lib_path)
slots = pkcs11.getSlotList(tokenPresent=True),
Slot_ID = len(slots[0])-1
# Belirli bir slot üzerinde yeni bir token oluştur
# slot_id = 2  # Slot ID'sini uygun bir şekilde değiştirin
# new_token_label = 'Denemelik'+' '*32  # Yeni token'ın etiketi
# SO_PIN = "1111"  # Yeni kullanıcı PIN'i
# User_PIN = "1111"
# # Token oluşturma işlemi (bu sadece örnek bir kullanım)
# pkcs11.initToken(slot_id, SO_PIN, new_token_label)
# pkcs11 = PyKCS11.PyKCS11Lib()
# pkcs11.load()
# slot = pkcs11.getSlotList(tokenPresent=True)[slot_id]
# session = pkcs11.openSession(slot, PyKCS11.CKF_RW_SESSION)
# session.login(SO_PIN, PyKCS11.CKU_SO)
# session.initPin(User_PIN)
# session.logout()
# session.closeSession()

