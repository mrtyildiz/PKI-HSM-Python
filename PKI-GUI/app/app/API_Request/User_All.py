
import requests
import os

ROOT_API_URL = os.environ.get("API_URL")

#### User All Obje ####

def Check_Token_Slot_Request(Token):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    data = {
        "TokenName": Token
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    message = response.json()
    Return_Message = message['Message: ']
    if Return_Message == 'Token not found':
        healthy = "unhealthy"
    else:
        healthy = "healthy"
    return healthy

def Users_Obje_all(TokenID,TokenPIN):
    URL = ROOT_API_URL + "User_Info_All/"
    data = {
        "ID": TokenID,
        "PIN": TokenPIN
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    return response.json()



#### User Create Start #####
def TokenIDFind(Token):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    data = {
        "TokenName": Token
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    message = response.json()
    return message

def User_Create_Request(ID,PIN,User_Name, Parola):
    URL = ROOT_API_URL + "UserCreate/"
    data = {

        "SlotID": ID,
        "SlotPIN": PIN,
        "UserName": User_Name,
        "Parola": Parola
    }
    response = requests.post(URL, json=data)

def Users_Obje_Delete(TokenID,TokenPIN,User_Name):
    URL = ROOT_API_URL + "UserObjeRemove/"
    data = {
        "SlotID": TokenID,
        "SlotPIN": TokenPIN,
        "UserName": User_Name
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    return response.json()
