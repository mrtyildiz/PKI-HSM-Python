import requests
import os

ROOT_API_URL = os.environ.get("API_URL")

def RSA_Create_Request(ID,PIN,Key_Name, BIT):
    URL = ROOT_API_URL + "RSACreate/"
    data = {

        "ID": ID,
        "PIN": PIN,
        "KName": Key_Name,
        "BIT": BIT
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())
    return response

def AES_Create_Request(ID,PIN,Key_Name, BIT):
    URL = ROOT_API_URL + "AESCreate/"

    data = {
        "SlotID": ID,
        "SlotPIN": PIN,
        "AES_KeyName": Key_Name,
        "BIT": BIT
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())
    return response

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
    # return response.json()
