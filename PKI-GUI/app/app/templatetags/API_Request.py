import requests
import os
# Hedef URL
ROOT_API_URL = os.environ.get("API_URL")

# Göndermek istediğiniz veri (örneğin, bir JSON nesnesi)

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
    print(response.json())

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

def CSR_T_CRT(
    rsa_key_path,
    csr_file_path,
    CompanyName,
    pin,
    slot_id,
    ca_crt_name,
    ca_key_name
):
    URL = ROOT_API_URL + "CSR_To_CRT/"
    files = {
    'rsa_key': ('private_key.pem', open(rsa_key_path, 'rb'), 'application/x-pem-file'),
    'csr_file': ('HiyTech.com.csr', open(csr_file_path, 'rb'), 'application/x-pem-file')
    }
    data = {
    'CompanyName': CompanyName,
    'pin': pin,
    'slot_id': slot_id,
    'ca_crt_name': ca_crt_name,
    'ca_key_name': ca_key_name
    }

    session = requests.Session()
    response = session.post(URL, files=files, data=data)

    if response.status_code == 200:
        crt_data = response.json()["Sertifika Data "]
        return crt_data
    else:
        raise Exception("Request failed with status code {}".format(response.status_code))
# rsa_key_path = "./private_key.pem"
# csr_file_path = "./HiyTech.com.csr"
# CompanyName = "procenne"
# pin = "1111"
# slot_id = 0
# ca_crt_name = "CAKeysprivCA"
# ca_key_name = "CAKeyspriv"
# a = CSR_T_CRT(rsa_key_path,csr_file_path,CompanyName,pin,slot_id,ca_crt_name,ca_key_name)
# print(a)


def DownloadsRequest(FileName,FileType):
    # Hedef URL
    URL = ROOT_API_URL + 'download/'

    # URL parametreleri
    params = {
        'file_name': FileName,
        'file_type': FileType
    }

    # GET isteği gönderme
    response = requests.post(URL, params=params)
    # Yanıtı işleme
    if response.status_code == 200:
        # Dosya içeriğini bir dosyaya kaydetmek için:
        with open(FileName, 'wb') as dosya:
            dosya.write(response.content)
        print('Dosya başarıyla indirildi.')
    else:
        print('Hata:', response.status_code)
        print('Hata mesajı:', response.text)

# FileName = "HiyTech.crt"
# FileType = "Certificate"
# DownloadsRequest(FileName,FileType)

### User Create Request ####

def User_Create_Request(ID,PIN,User_Name, Parola):
    URL = ROOT_API_URL + "UserCreate/"
    data = {

        "SlotID": ID,
        "SlotPIN": PIN,
        "UserName": User_Name,
        "Parola": Parola
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())

# ID = 0
# Slot_PIN = "1111"
# UserName = "Murat"
# Parola = "1q2w3e4r5t*"
# User_Create_Request(ID,Slot_PIN,UserName,Parola)

def User_Verify_Request(ID,PIN,User_Name, Parola):
    URL = ROOT_API_URL + "UserVerify/"
    data = {
        "SlotID": ID,
        "SlotPIN": PIN,
        "UserName": User_Name,
        "Parola": Parola
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())

# ID = 0
# Slot_PIN = "1111"
# UserName = "Murat"
# Parola = "1q2w3e4r5t*"
# User_Verify_Request(ID,Slot_PIN,UserName,Parola)

def Certificate_Info_All_Request(ID,PIN):
    URL = ROOT_API_URL + "Certificate_Info_All/"
    data = {
        "ID": ID,
        "PIN": PIN
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())

# id = 0
# pin = "1111"
# Certificate_Info_All_Request(id,pin)

def Certificate_Info_Request(ID,PIN,CertificateName):
    URL = ROOT_API_URL + "Certificate_Info/"
    data = {
        "ID": ID,
        "PIN": PIN,
        "CertificateName": CertificateName
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())

# id = 0
# pin = "1111"
# CertificateName = "CAKeysprivCA"
# Certificate_Info_Request(id,pin,CertificateName)

def CRT_Verifty_Request(
    crt_file_path,
    CACertificateName,
    pin,
    slot_id
):
    URL = ROOT_API_URL + "CRT_Verifty/"
    files = {
    'crt_file': ('HiyTech.crt', open(crt_file_path, 'rb'), 'application/x-pem-file')
    }
    data = {
    'CACertificateName': CACertificateName,
    'pin': pin,
    'slot_id': slot_id
    }

    session = requests.Session()
    response = session.post(URL, files=files, data=data)
    print(response.json())

# crt_file_path = "./HiyTech.crt"
# CACertificateName = "CAKeysprivCA"
# pin = "1111"
# slot_id = 0
# CRT_Verifty_Request(crt_file_path,CACertificateName,pin,slot_id)

def Create_JWT_Request(
    crt_file_path,
    CACertificateName,
    pin,
    slot_id
):
    URL = ROOT_API_URL + "Create_JWT/"
    files = {
    'crt_file': ('HiyTech.crt', open(crt_file_path, 'rb'), 'application/x-pem-file')
    }
    data = {
    'CACertificateName': CACertificateName,
    'pin': pin,
    'slot_id': slot_id
    }

    session = requests.Session()
    response = session.post(URL, files=files, data=data)
    print(response.json())

# crt_file_path = "./HiyTech.crt"
# CACertificateName = "CAKeysprivCA"
# pin = "1111"
# slot_id = 0
# Create_JWT_Request(crt_file_path,CACertificateName,pin,slot_id)


#### Hatalı yeniden Bak ####
# def JWT_Verifty_Request(Token):
#     URL = ROOT_API_URL + "Verifty-JTW-Token/"
#     data = {
#         "tokens": Token
#     }

#     session = requests.Session()
#     response = session.post(URL, data=data)
#     print(response.json())

# Token = Create_JWT_Request(crt_file_path,CACertificateName,pin,slot_id)
# JWT_Verifty_Request(Token)

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

# ID = 0
# PIN = "1111"
# ObjeType = "Public"
# ObjeLabel = "pub"
# Obje_Remove_Request(ID,PIN,ObjeType,ObjeLabel)

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
    print(response.json())

# ID = 0
# PIN = "1111"
# KeyName = "priv"
# Country = "TR"
# City = "Ankara"
# Company = "Procenne"
# Common_Name = "Procenne_Corp"
# CompanyID = "17272727"
# CSR_Request_HSM_Request(ID,PIN,KeyName,Country,City,Company,Common_Name,CompanyID)

def CSR_HSM_CRT_Request(
    csr_file_path,
    CompanyName,
    pin,
    slot_id,
    ca_crt_name,
    ca_key_name
):
    with open(csr_file_path, "r") as dosya:
        print("Dosya adı:", dosya.name)
    URL = ROOT_API_URL + "CSR_HSM_CRT/"
    files = {
    'csr_file': ('HiyTech.crt', open(csr_file_path, 'rb'), 'application/x-pem-file')
    }
    data = {
    'CompanyName': CompanyName,
    'pin': pin,
    'slot_id': slot_id,
    'ca_crt_name' : ca_crt_name,
    'ca_key_name' : ca_key_name 
    }

    session = requests.Session()
    response = session.post(URL, files=files, data=data)
    print(response.json())

# csr_file_path = "./Procenne.csr"
# CompanyName = "Procenne"
# pin = "1111"
# slot_id = 0
# ca_crt_name = "CACrt"
# ca_key_name = "PrivKey"

# CSR_HSM_CRT_Request(csr_file_path,CompanyName,pin,slot_id,ca_crt_name,ca_key_name)

def Two_Factör_Request(ID,PIN,Char):
    URL = ROOT_API_URL + "Two_Factör/"
    data = {
        "SlotID": ID,
        "SlotPIN": PIN,
        "Character": Char
     }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())

# ID = 0
# PIN = "1111"
# Char = 10
# Two_Factör_Request(ID,PIN,Char)

def AES_Data_Encryption_Request(ID,PIN,KeyName,Data,init_Vector_str):
    URL = ROOT_API_URL + "AES_Data_Encryption/"
    data = {
        "SlotID": ID,
        "SlotPIN": PIN,
        "KeyName": KeyName,
        "Data": Data,
        "init_Vector_str": init_Vector_str
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())

# ID = 0
# PIN = "1111"
# KeyName = "AESKey"
# Data = "deneme"
# init_Vector_str = "4b04ae274cc4181cb2ee8ca9cdbb11d3"
# AES_Data_Encryption_Request(ID,PIN,KeyName,Data,init_Vector_str)

def AES_Data_Decryption_Request(ID,PIN,KeyName,Data,init_Vector_str):
    URL = ROOT_API_URL + "AES_Data_Decryption/"
    data = {
        "SlotID": ID,
        "SlotPIN": PIN,
        "KeyName": KeyName,
        "Data": Data,
        "init_Vector_str": init_Vector_str
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())

# ID = 0
# PIN = "1111"
# KeyName = "AESKey"
# Data = "5e9fd5f9675f20c501f95a49f14b4fae"
# init_Vector_str = "4b04ae274cc4181cb2ee8ca9cdbb11d3"
# AES_Data_Decryption_Request(ID,PIN,KeyName,Data,init_Vector_str)

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

# ID = 0
# PIN = "1111"
# KeyName = "pub"
# PublicKeyExport_Request(ID,PIN,KeyName)

def CertificateExport_Request(ID,CertName):
    URL = ROOT_API_URL + "CertificateExport/"
    data = {
        "SlotID": ID,
        "CertificateName": CertName
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    print(response.json())

# ID = 0
# CertName = "HiyTech"
# CertificateExport_Request(ID,CertName)


# Token = "PKI_DB"
# a = Check_Token_Slot_Request(Token)
# print(a)

def Danger_Token_Slot_Request(Token):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    data = {
        "TokenName": Token
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    message = response.json()
    Return_Message = message['Message: ']
    if Return_Message == 'Token not found':
        healthy = "danger"
    else:
        healthy = "success"
    return healthy