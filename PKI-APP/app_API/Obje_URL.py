import os
import json
def Search_Find(array, target):
    result = []

    for dize in array:
        if target in dize:
            result.append(dize)

    return result

def get_tokens(ID,Slot_PIN):
    Command_1 = "p11tool --login --provider=/lib64/libprocryptoki.so --list-tokens | grep URL"
    Command_1_Runs = os.popen(Command_1).read()  # Komut çıktısını oku
    lines = Command_1_Runs.strip().split('\n')  # Satırlara ayır
    Labels = lines[ID].split(': ')
    Slot_Label = str(Labels[1])
    Command_2 = f'p11tool --login --provider=/lib64/libprocryptoki.so --list-all "{Slot_Label}?pin-value={Slot_PIN}" | grep URL'
    Command_2_Runs = os.popen(Command_2).read()  # Komut çıktısını oku
    lines_obje = Command_2_Runs.strip().split('\n')  # Satırlara ayır
    Private_Key = "type=private"
    Privates = Search_Find(lines_obje, Private_Key)
    Private_URL = Privates[0].split(': ')[1]
    Cetificate = "type=cert"
    Cetificates = Search_Find(lines_obje, Cetificate)
    Cetificate_URL = Cetificates[0].split(': ')[1]
    message = {
        "Key_Priv": Private_URL,
        "Certificat": Cetificate_URL
    }
    # JSON mesajını bir dizeye çevir
    json_message = json.dumps(message)
    
    return json_message
# ID = 0
# pin = "1111"
# a = get_tokens(ID,pin)
# print(a)
