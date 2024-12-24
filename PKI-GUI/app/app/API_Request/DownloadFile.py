import requests
import os
ROOT_API_URL = os.environ.get("API_URL")

def CertificateExport_Request(ID,CertName):
    URL = ROOT_API_URL + "CertificateExport/"
    data = {
        "SlotID": ID,
        "CertificateName": CertName
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())
    return response.json()

def PublicKeyExport_Request(ID,PIN,KeyName):
    URL = ROOT_API_URL + "PublicKeyExport/"
    data = {
        "SlotID": ID,
        "SlotPIN": PIN,
        "PublicKeyName": KeyName
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())