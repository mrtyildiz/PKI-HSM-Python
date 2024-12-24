import requests
import os

ROOT_API_URL = os.environ.get("API_URL")

def Obje_Remove_Request(ID,PIN,ObjeType,ObjeLabel):
    URL = ROOT_API_URL + "Obje_Remove/"
    data = {
        "ID": ID,
        "Slot_PIN": PIN,
        "ObjeType": ObjeType,
        "ObjeLabel": ObjeLabel
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())


def CRTAll_File(Slot,UserPIN,KeyName,CRT_Name):
    CertType = "Certificate"
    print(UserPIN)
    Obje_Remove_Request(Slot,UserPIN,CertType,CRT_Name)
    PublicType = "Public"
    PrivateType = "Private"
    PrivKey = KeyName +"priv"
    PubKey = KeyName + "pub"
    Obje_Remove_Request(Slot,UserPIN,PublicType,PubKey)
    Obje_Remove_Request(Slot,UserPIN,PrivateType,PrivKey)
