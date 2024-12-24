
import requests
import os
ROOT_API_URL = os.environ.get("API_URL")

### CSR Create Start ###
def CSR_Request_HSM_Request(ID,PIN,KeyName,Country,City,Company,Common_Name,CompanyID):
    URL = ROOT_API_URL + "CSR_Request_HSM/"
    data = {
        "SlotID": ID,
        "SlotPIN": PIN,
        "KeyName": KeyName,
        "Country": Country,
        "City": City,
        "Company": Company,
        "Common_Name": Common_Name,
        "CompanyID": CompanyID
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    return response.json()

def CSR_Create(Slot_ID,Token_PIN,KeyPriv,Country,City,Company,Company_Name,Company_ID):
    Array_File = CSR_Request_HSM_Request(Slot_ID,Token_PIN,KeyPriv,Country,City,Company,Company_Name,Company_ID)
    print(Array_File)
    File = Array_File['message:']
    File_Path = "/app"+str(File)
    return File_Path
# KeyName = "RSADeneme"

def Danger_Token_Slot_Request(Token):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    data = {
        "TokenName": Token
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    message = response.json()
    return message
