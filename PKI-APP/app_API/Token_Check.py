import os
from PyKCS11 import *
import json


def Check_Token(target_label):
    # PKCS#11 uyumlu cihazın kütüphane yolunu belirtin
    library_path = os.environ.get('PYKCS11LIB')
    # PKCS#11 modülünü yükle
    pkcs11 = PyKCS11Lib()
    pkcs11.load(library_path)
  #  Slot_List = pkcs11.getSlotList(tokenPresent=True)
    # PKCS#11 uyumlu cihazları listeleyin
    try:
        slots = pkcs11.getSlotList()

        if not slots:
            print("Hiçbir PKCS#11 uyumlu cihaz bulunamadı.")
            exit()
        # Her bir slotta tokenları kontrol edin 
        target_label_array = char_list = [char for char in target_label]

        for slot in slots:
            token = pkcs11.getTokenInfo(slot)
            label = token.label
            new_label = label.replace(' ', '')
            if new_label.upper() == target_label.upper():
                slot_info = {
                    "slot_id": slot,
                    "slot_name": target_label
                    }
                # message = json.dumps(slot_info)
                message = slot_info
                break  # İlk eşleşen token'ı bulduktan sonra döngüden çıkabilirsiniz.
            else:
                pass
        else:
            message = "Token not found"
        return message
    except:
        message = "Token not found"
        return message

# label = "CA_Slot2"
# a = Check_Token(label)
# print(a)