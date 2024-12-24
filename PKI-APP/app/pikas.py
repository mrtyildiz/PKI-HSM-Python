import pika
import json
import requests
import os
from Slot_Intialized_Merge import Token_Create
from Certificate_Info_Single import Cert_InfoSing
from Obje_Action import RemoveObje
from HSM_Action import ConfigFileWrite
from Action import Check_Token, CrtExport, PublicExport, Slot_Label_Func
from Key_Action import RSA_Create, AES_Creates, EC_Create
from User_Action import User_Infos, User_Obje_Create_Func, User_Delete
from Slot_PIN_Action import Slot_Find
from Verify_Action import verify_certificate
from Certificate_Action import VeriftyCRT, CSR_Create_New, Cert_Info
from CA_Certificate_Request2 import CARequestCertificate2
from CSR_HSM_CRT import HSM_CSR
from Certificate_Loads import Certificate_Load
from Find_Label_Priv import Find_Label_Obje
from File_Action import encrypt_file, decrypt_file
import base64
ROOT_API_URL = "http://localhost:8000/"
Rabbit_Host = os.environ.get("Rabbit_Host")
RabbitUser = os.environ.get("RabbitUser")
RabbitPassword = os.environ.get("RabbitPassword")
def on_request(ch, method, properties, body):
    # İstek verilerini al
    request_data = json.loads(body.decode("utf-8"))
    Endpoint = request_data["Endpoint"]
    if "Endpoint" in request_data:
        del request_data["Endpoint"]
    response_data = Main_Request(Endpoint, request_data)
    
    # Yanıtı gönder
    ch.basic_publish(
        exchange='',
        routing_key=properties.reply_to,
        properties=pika.BasicProperties(correlation_id=properties.correlation_id),
        body=json.dumps(response_data)
    )
    ch.basic_ack(delivery_tag=method.delivery_tag)

def Active_HSM_Request(data):
    IP_Address = data['IP_Address']
    Port_Address = data['Port_Address']
    message = ConfigFileWrite(IP_Address,Port_Address)
    return {"message": message}

def FindID(data):
    print("FindID"+str(data))
    URL = ROOT_API_URL + "Check_Token_Slot/"
    response = requests.post(URL, json=data)
    return response.json()

def RSA_Create_Request(data):
    Slot_ID = data['ID']
    Slot_PIN = data['PIN']
    KeyName = data['KName']
    BIT = int(data['BIT'])
    result = RSA_Create(Slot_ID,Slot_PIN,KeyName,BIT)
    if result:
        messages = str(KeyName)+ " key was created"
    else:
        messages = str(KeyName)+ " key was not created"
    return {"message:": messages}



def CA_Create_Request(data):
    print("CA_Create_Request"+str(data))
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    CertificateFile = data['CertificateFile']
    CertificateName = data['CertificateName']
    URL = ROOT_API_URL + "CARequest/"
    response = requests.post(URL, json=data)
    return response.json()

def Danger_Token_Slot_Request(data):
    print("Danger_Token_Slot_Request"+str(data))
    URL = ROOT_API_URL + "Check_Token_Slot/"
    response = requests.post(URL, json=data)
    return response.json()

def Certificate_Info_Request(data):
    ID = int(data['ID'])
    PIN = data['PIN']
    CertificateName = data['CertificateName']
    
    result = Cert_InfoSing(ID,PIN,CertificateName)
    #filtrelenmis_veri = [veri for veri in result if veri['Certificate_Name'] == CertificateName]
    #return filtrelenmis_veri
    return result


def Certificate_Load_Request(data):
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    CertificateFile = data['CertificateFile']
    CertificateName = data['CertificateName']
    result =Certificate_Load(SlotID,SlotPIN,CertificateFile,CertificateName)
    return result


def CSR_Request_HSM_Request(data):
    print("CSR_Request_HSM_Request"+str(data))
    URL = ROOT_API_URL + "CSR_Request_HSM/"
    response = requests.post(URL, json=data)
    return response.json()

def CSR_HSM_CRT_Request(data):

    files = data['files']
    files_name = files.split('/')
    file_name = files_name[-1]
    CompanyName = data['CompanyName']
    print(CompanyName)
    pin = data['pin']
    slot_id = int(data['slot_id'])
    ca_crt_name = data['ca_crt_name']
    ca_key_name = data['ca_key_name']
    Days = int(data['Days'])
    result = HSM_CSR(slot_id,pin,ca_key_name,file_name,ca_crt_name,Days,CompanyName)
    print(result)
    return {"Message: ": result}

def CertificateExport_Request(data):

    Slot_ID = data['SlotID']
    ca_cert_label = data['CertificateName']
    result = CrtExport(Slot_ID,ca_cert_label)
    message = {"Message:": result}
    return message

def PublicKeyExport_Request(data):
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    PublicKeyName = data['PublicKeyName']
    result = PublicExport(SlotID,SlotPIN,PublicKeyName)
    message = {"Message:": result}
    return message

def AES_Create_Request(data):
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    AES_KeyName = data['AES_KeyName']
    BIT = int(data['BIT'])
    result = AES_Creates(SlotID,SlotPIN,AES_KeyName,BIT)
    if result:
        messages = str(AES_KeyName)+ " key was created"
    else:
        messages = str(AES_KeyName)+ " key was not created"
    return {"message:": messages}

def Obje_Remove_Request(data):
    slot_id = data['ID']
    slot_pin = data['Slot_PIN']
    ObjeType = data['ObjeType']
    Obje_Label = data['ObjeLabel']
    message = RemoveObje(slot_id,slot_pin,ObjeType,Obje_Label)
    result = {"Message: ": message}
    return result

def Check_Token_Slot_Request(data):
    print("Check_Token_Slot_Request"+str(data))
    URL = ROOT_API_URL + "Check_Token_Slot/"

    response = requests.post(URL, json=data)
    return response.json()

def Users_Obje_all(data):

    SlotID = data['ID']
    SlotPin = data['PIN']
    try:
        result = User_Infos(SlotID,SlotPin)
    except:
        result = []
    return result

def TokenIDFind(data):
    TokenName = data['TokenName']
    result = Check_Token(TokenName)
    message = {"Message: ": result}
    return message


def User_Create_Request(data):
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    UserName = data['UserName']
    Parola = data['Parola']
    result = User_Obje_Create_Func(SlotID,SlotPIN,UserName,Parola)
    return {"user Response": result}

def Users_Obje_Delete(data):
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    UserName = data['UserName']
    message = User_Delete(SlotID,SlotPIN,UserName)
    print(message)
    result = {"Message: ": message}
    return result

def Certificate_ALL(data):

    SlotID = data['ID']
    SlotPin = data['PIN']
    try:
        result = Cert_Info(SlotID,SlotPin)
    except:
        result = []
    return result

def Obje_Find_URL(data):
    print("Obje_Find_URL"+str(data))
    URL = ROOT_API_URL + "Obje_Find_URL/"
    response = requests.post(URL, json=data)
    return response.json()
def Find_Obje(data):
    Slot_ID = data['Slot_ID']
    Slot_PIN = data['Slot_PIN']
    Obje_Label = data['Obje_Label']
    result = Find_Label_Obje(Slot_ID,Slot_PIN,Obje_Label)
    return {"message": result}

def Slot_PIN_ENC_DEC(data):
    API_Key = data['API_Key']
    Action = data['Action']
    Strings_Slot_PIN = data['Strings_Slot_PIN']
    result = Slot_Find(API_Key,Action,Strings_Slot_PIN)
    print(result)
    return {"Message:": result}

def UserVerify_Rabbit(data):
    print("UserVerify_Rabbit"+str(data))
    URL = ROOT_API_URL + "UserVerify/"
    response = requests.post(URL, json=data)
    return response.json()

def FileEncrypt(data):
    Slot_ID = data['ID']
    Slot_PIN = data['PIN']
    init_vector = base64.b64decode(data['init_vector'])
    KName = data['KName']
    FNamePath = data['FNamePath']
    result = encrypt_file(Slot_ID, Slot_PIN, FNamePath, KName, init_vector)
    return {"Message:": result}


def FileDecrypt(data):
    Slot_ID = data['ID']
    Slot_PIN = data['PIN']
    init_vector = base64.b64decode(data['init_vector'])
    KName = data['KName']
    FNamePath = data['FNamePath']
    result = decrypt_file(Slot_ID, Slot_PIN, FNamePath, KName, init_vector)
    return {"Message:": result}

def CA_Create_Request_2(data):
    Slot_ID = int(data['Slot_ID'])
    Slot_PIN = data['Slot_PIN']
    PrivateKeyName = data['PrivateKeyName']
    Days = int(data['Days'])
    datas = data['data']
    CA_Files = CARequestCertificate2(Slot_ID,Slot_PIN,PrivateKeyName,Days,datas)
    return {"CA_Sertifikasi": CA_Files}

def CSR_Create_New2(data):
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    KeyName = data['KeyName']
    Company = data['Company']
    Json_Data = data['Json_Data']
    result = CSR_Create_New(SlotID,SlotPIN,KeyName,Company,Json_Data)
    return { "message:" : result}

def ECCreate(data):
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    KeyLabel = data['KeyLabel']
    Algoritma = data['Algoritma']
    result = EC_Create(SlotID,SlotPIN,KeyLabel,Algoritma)
    if result:
        messages = "Created EC Key named "+str(KeyLabel)
    else:
        messages = "Created EC Key named "+str(KeyLabel)
    return {"message:": messages}  


def CRT_Verifty_Request(data):
    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    CA_CRT = data['CA_CRT']
    CRT_Name = data['CRT_Name']
    result = VeriftyCRT(SlotID,SlotPIN,CA_CRT,CRT_Name)
    return {"Verifty": result}


def CRT_Key_Verifty_Request(data):

    SlotID = data['SlotID']
    SlotPIN = data['SlotPIN']
    KeyName = data['KeyName']
    CRT_Name = data['CRT_Name']
    result = verify_certificate(CRT_Name, SlotID, SlotPIN, KeyName)
    return {"message:": result}

def HSM_Tokens_Request(data):
    result = Slot_Label_Func()
    return {"message": result}


def New_Token_Request(data):
    URL = ROOT_API_URL + "New_Token_Create/"
    Token_Label = data['Token_Label']
    ho_pin = data['ho_pin']
    ha_pin = data['ha_pin']
    SO_PIN = data['SO_PIN']
    User_PIN = data['User_PIN']
    result = Token_Create(ho_pin,ha_pin,Token_Label,SO_PIN,User_PIN)    #response = requests.post(URL)

    return result #response.json()

def default_function(data):
    return f"Bilinmeyen durumun işlevi çalıştı. Veri: {data}"

def Main_Request(case, data):
    switch_dict = {
        'HSM_Pool_Active/': Active_HSM_Request,
        'Check_Token_Slot/': FindID,
        'RSACreate/': RSA_Create_Request,
        'CARequest/': CA_Create_Request,
        'Certificate_Info/': Certificate_Info_Request,
        'LoadCertificate/': Certificate_Load_Request,
        'CSR_Request_HSM/': CSR_Request_HSM_Request,
        'CSR_HSM_CRT/': CSR_HSM_CRT_Request,
        'Check_Token_Slot/': Danger_Token_Slot_Request,
        'CertificateExport/': CertificateExport_Request,
        'PublicKeyExport/': PublicKeyExport_Request,
        'RSACreate/': RSA_Create_Request,
        'AESCreate/': AES_Create_Request,
        'Obje_Remove/': Obje_Remove_Request,
        'Check_Token_Slot/': Check_Token_Slot_Request,
        'User_Info_All/': Users_Obje_all,
        'Check_Token_Slot/': TokenIDFind,
        'UserCreate/': User_Create_Request,
        'UserObjeRemove/': Users_Obje_Delete,
        'Certificate_Info_All/' : Certificate_ALL,
        'Label_Obje_Find/' : Find_Obje,
        'Obje_Find_URL/' : Obje_Find_URL,
        'Slot_Find_PIN/': Slot_PIN_ENC_DEC,
        'UserVerify/' : UserVerify_Rabbit,
        'FileEncPYHSM/' : FileEncrypt,
        'FileDecPYHSM/' : FileDecrypt,
        'CARequestNew/' : CA_Create_Request_2,
        'CSR_Request_HSM_New/' : CSR_Create_New2,
        'EC_Create/' : ECCreate,
        'CRT_Verifty_Request/': CRT_Verifty_Request,
        'verify_certificate_key/':CRT_Key_Verifty_Request,
        'HSM_Tokens/' : HSM_Tokens_Request,
        'New_Token_Create/': New_Token_Request,

    }
    
    selected_function = switch_dict.get(case, default_function)
    return selected_function(data)



### Sistem başlatıldı.
connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        Rabbit_Host,
        credentials=pika.PlainCredentials(RabbitUser, RabbitPassword)
    )
)
channel = connection.channel()

channel.queue_declare(queue='api_queue')
channel.basic_consume(queue='api_queue', on_message_callback=on_request)

print("API Sunucusu Başlatıldı. İstekleri Dinliyor...")
channel.start_consuming()
