import requests
from datetime import datetime
import os
ROOT_API_URL = os.environ.get("API_URL")


##### CA Sertifika işlemi ####

def FindID(Token):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    data = {
        "TokenName": Token
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    message = response.json()
    return message

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
    return response.json()


def CA_Create_Request(ID,PIN,Key_Name, CommonName,OrganizationName,CountryName):
    URL = ROOT_API_URL + "CARequest/"

    data = {
        "Slot_ID": ID,
        "Slot_PIN": PIN,
        "PrivateKeyName": Key_Name,
        "CommonName": CommonName,
        "OrganizationName": OrganizationName,
        "CountryName": CountryName
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    return response.json()


def Danger_Token_Slot_Request(Token):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    data = {
        "TokenName": Token
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    message = response.json()
    return message
def Certificate_Info_Request(ID,PIN,CertificateName):
    URL = ROOT_API_URL + "Certificate_Info/"
    data = {
        "ID": ID,
        "PIN": PIN,
        "CertificateName": CertificateName
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    return response.json()

def Certificate_Load_Request(ID,PIN,CertPATH,CertName):
    URL = ROOT_API_URL + "LoadCertificate/"

    data = {
        "SlotID": ID,
        "SlotPIN": PIN,
        "CertificateFile": CertPATH,
        "CertificateName": CertName
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())
