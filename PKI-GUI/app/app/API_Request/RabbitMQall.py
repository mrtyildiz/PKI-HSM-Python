import pika
import uuid
import json
import os


Rabbit_Host = os.environ.get("Rabbit_Host")
RabbitUser = os.environ.get("RabbitUser")
RabbitPassword = os.environ.get("RabbitPassword")

class APIClient:
    def __init__(self, host, username, password):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host,
                credentials=pika.PlainCredentials(username, password)
            )
        )
        self.channel = self.connection.channel()

        result = self.channel.queue_declare(queue='', exclusive=True)
        self.callback_queue = result.method.queue

        self.channel.basic_consume(queue=self.callback_queue, on_message_callback=self.on_response, auto_ack=True)

    def on_response(self, ch, method, properties, body):
        if self.corr_id == properties.correlation_id:
            self.response = body

    def call_api(self, request_data):
        self.response = None
        self.corr_id = str(uuid.uuid4())
        self.channel.basic_publish(
            exchange='',
            routing_key='api_queue',
            properties=pika.BasicProperties(
                reply_to=self.callback_queue,
                correlation_id=self.corr_id,
            ),
            body=json.dumps(request_data)
        )
        while self.response is None:
            self.connection.process_data_events()
        return self.response


def Active_HSM_Request(IP_Address,Port_Address):
    data = {
        "Endpoint":"HSM_Pool_Active/",
        "IP_Address": IP_Address,
        "Port_Address": Port_Address
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

# IP = "172.16.0.2"
# Port = "5000"
# Active_HSM_Request(IP,Port)

def FindID(Token):
    data = {
        "Endpoint":"Check_Token_Slot/",
        "TokenName": Token
    }
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

# Token = "PKI_DB"
# FindID(Token)

def RSA_Create_Request(ID,PIN,Key_Name, BIT):
    data = {
        "Endpoint":"RSACreate/",
        "ID": ID,
        "PIN": PIN,
        "KName": Key_Name,
        "BIT": BIT
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def CA_Create_Request(ID,PIN,Key_Name, CommonName,OrganizationName,CountryName):
    data = {
        "Endpoint":"CARequest/",
        "Slot_ID": ID,
        "Slot_PIN": PIN,
        "PrivateKeyName": Key_Name,
        "CommonName": CommonName,
        "OrganizationName": OrganizationName,
        "CountryName": CountryName
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Danger_Token_Slot_Request(Token):
    data = {
        "Endpoint":"Check_Token_Slot/",
        "TokenName": Token
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Certificate_Info_Request(ID,PIN,CertificateName):
    data = {
        "Endpoint":"Certificate_Info/",
        "ID": ID,
        "PIN": PIN,
        "CertificateName": CertificateName
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Certificate_Load_Request(ID,PIN,CertPATH,CertName):

    data = {
        "Endpoint": "LoadCertificate/",
        "SlotID": ID,
        "SlotPIN": PIN,
        "CertificateFile": CertPATH,
        "CertificateName": CertName
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

### CSR Create Start ###
def CSR_Request_HSM_Request(ID,PIN,KeyName,Country,City,Company,Common_Name,CompanyID):
    data = {
        "Endpoint": "CSR_Request_HSM/",
        "SlotID": ID,
        "SlotPIN": PIN,
        "KeyName": KeyName,
        "Country": Country,
        "City": City,
        "Company": Company,
        "Common_Name": Common_Name,
        "CompanyID": CompanyID
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def CSR_Create(Slot_ID,Token_PIN,KeyPriv,Country,City,Company,Company_Name,Company_ID):
    Array_File = CSR_Request_HSM_Request(Slot_ID,Token_PIN,KeyPriv,Country,City,Company,Company_Name,Company_ID)
    print(Array_File)
    File = Array_File['message:']
    File_Path = "/app"+str(File)
    return File_Path
# KeyName = "RSADeneme"

def Danger_Token_Slot_Request(Token):
    data = {
        "Endpoint": "Check_Token_Slot/",
        "TokenName": Token
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def CSR_HSM_CRT_Request(csr_file_path,crt_file_name,CompanyName,pin,slot_id,ca_crt_name,ca_key_name,Days):
    # with open(csr_file_path, "r") as dosya:
    #     print("Dosya adı:", dosya.name)
    # files = {
    # 'csr_file': (crt_file_name, open(csr_file_path, 'rb'), 'application/x-pem-file')
    # }
    data = {
        'Endpoint': 'CSR_HSM_CRT/',
        'files': csr_file_path,
        'CompanyName': CompanyName,
        'pin': pin,
        'slot_id': slot_id,
        'ca_crt_name' : ca_crt_name,
        'ca_key_name' : ca_key_name,
        'Days':Days
    }

    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Danger_Token_Slot_Request(Token):
    data = {
        "Endpoint": "Check_Token_Slot/",
        "TokenName": Token
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def CertificateExport_Request(ID,CertName):
    data = {
        "Endpoint": "CertificateExport/",
        "SlotID": ID,
        "CertificateName": CertName
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def PublicKeyExport_Request(ID,PIN,KeyName):
    data = {
        "Endpoint": "PublicKeyExport/",
        "SlotID": ID,
        "SlotPIN": PIN,
        "PublicKeyName": KeyName
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def RSA_Create_Request(ID,PIN,Key_Name, BIT):
    data = {
        "Endpoint": "RSACreate/",
        "ID": ID,
        "PIN": PIN,
        "KName": Key_Name,
        "BIT": BIT
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


def AES_Create_Request(ID,PIN,Key_Name, BIT):
    data = {
        "Endpoint": "AESCreate/",
        "SlotID": ID,
        "SlotPIN": PIN,
        "AES_KeyName": Key_Name,
        "BIT": BIT
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


def Obje_Remove_Request(ID,PIN,ObjeType,ObjeLabel):
    data = {
        "Endpoint": "Obje_Remove/",
        "ID": ID,
        "Slot_PIN": PIN,
        "ObjeType": ObjeType,
        "ObjeLabel": ObjeLabel
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


# def Obje_Remove_Request(ID,PIN,ObjeType,ObjeLabel):
#     data = {
#         "ID": ID,
#         "Slot_PIN": PIN,
#         "ObjeType": ObjeType,
#         "ObjeLabel": ObjeLabel
#     }
#     # Rabbitmq İsteği gönderin
#     api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
#     response = api_client.call_api(data)
#     api_client.connection.close()
#     json_string = response.decode('utf-8')
#     json_object = json.loads(json_string)
#     return json_object


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


#### User All Obje ####

def Check_Token_Slot_Request(Token):
    data = {
        "Endpoint": "Check_Token_Slot/",
        "TokenName": Token
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
   # return json_object
    Return_Message = json_object['Message: ']
    if Return_Message == 'Token not found':
        healthy = "unhealthy"
    else:
        healthy = "healthy"
    return healthy

def Users_Obje_all(TokenID,TokenPIN):
    data = {
        "Endpoint": "User_Info_All/",
        "ID": TokenID,
        "PIN": TokenPIN
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


#### User Create Start #####
def TokenIDFind(Token):
    data = {
        "Endpoint": "Check_Token_Slot/",
        "TokenName": Token
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def User_Create_Request(ID,PIN,User_Name, Parola):
    data = {
        "Endpoint": "UserCreate/",
        "SlotID": ID,
        "SlotPIN": PIN,
        "UserName": User_Name,
        "Parola": Parola
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Users_Obje_Delete(TokenID,TokenPIN,User_Name):
    data = {
        "Endpoint": "UserObjeRemove/",
        "SlotID": TokenID,
        "SlotPIN": TokenPIN,
        "UserName": User_Name
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

# # Örnek veri
# request_data = {
#     "IP_Address": "172.16.0.5",
#     "Port_Address": "5000"
# }

# api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
# response = api_client.call_api(request_data)
# print("API Response:", response)
# api_client.connection.close()
def Certificate_ALL(ID,PIN):
    data = {
        "Endpoint":"Certificate_Info_All/",
        "ID": ID,
        "PIN": PIN
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Find_Obje(ID,PIN,ObjeLabel):
    data = {
        "Endpoint":"Label_Obje_Find/",
        "Slot_ID": ID,
        "Slot_PIN": PIN,
        "Obje_Label": ObjeLabel
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Obje_URL_Find(ID,PIN):
    data = {
        "Endpoint":"Obje_Find_URL/",
        "ID": ID,
        "PIN": PIN
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Slot_PIN_ENC_DEC(Action,PIN_Str):
    Real_API_Key = os.environ.get('API_Slot')
    data = {
        "Endpoint":"Slot_Find_PIN/",
        "API_Key": Real_API_Key,
        "Action": Action,
        "Strings_Slot_PIN": PIN_Str
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


def UserVerify_Rabbit(ID,PIN,Username,password):
    data = {
        "Endpoint":"UserVerify/",
        "SlotID": ID,
        "SlotPIN": PIN,
        "UserName": Username,
        "Parola": password
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def FileEncrypt(ID,PIN,KeyName,FileName):
    data = {
        "Endpoint":"FileEncPYHSM/",
        "ID": ID,
        "PIN": PIN,
        "init_vector": "2r4AlGJ7VsFS0AS1Dw4FCA==",
        "KName": KeyName,
        "FNamePath": FileName
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


def FileDecrypt(ID,PIN,KeyName,FileName):
    data = {
        "Endpoint":"FileDecPYHSM/",
        "ID": ID,
        "PIN": PIN,
        "init_vector": "2r4AlGJ7VsFS0AS1Dw4FCA==",
        "KName": KeyName,
        "FNamePath": FileName
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


def CA_Create_Request_2(ID,PIN,Key_Name, Days, data_dict):
    data = {
        "Endpoint":"CARequestNew/",
        "Slot_ID": ID,
        "Slot_PIN": PIN,
        "PrivateKeyName": Key_Name,
        "Days": Days,
        "data": data_dict
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def CSR_Create_New(Slot_ID,Token_PIN,KeyPriv,CommonName,DataJson):
    data = {
        "Endpoint":"CSR_Request_HSM_New/",
        "SlotID": Slot_ID,
        "SlotPIN": Token_PIN,
        "KeyName": KeyPriv,
        "Company": CommonName,
        "Json_Data": DataJson
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def EC_Create(Slot_ID,Token_PIN,KeyLabel,Algoritma):
    data = {
        "Endpoint":"EC_Create/",
        "SlotID": Slot_ID,
        "SlotPIN": Token_PIN,
        "KeyLabel": KeyLabel,
        "Algoritma": Algoritma
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


def CRT_Verifty_Request(Slot_ID,Token_PIN,CA_CRT_Name,CRT_Name):
    data = {
        "Endpoint":"CRT_Verifty_Request/",
        "SlotID": Slot_ID,
        "SlotPIN": Token_PIN,
        "CA_CRT": CA_CRT_Name,
        "CRT_Name": CRT_Name
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


def CRT_Key_Verifty_Request(Slot_ID,Token_PIN,KeyName,CRT_Name):
    data = {
        "Endpoint":"verify_certificate_key/",
        "SlotID": Slot_ID,
        "SlotPIN": Token_PIN,
        "KeyName": KeyName,
        "CRT_Name": CRT_Name
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def HSM_Tokens_Request():
    data = {
        "Endpoint":"HSM_Tokens/",
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def Token_Create(ho_pin,ha_pin,Token_Label,SO_PIN,User_PIN):
    data = {
        "Endpoint":"New_Token_Create/",
        "ho_pin": ho_pin,
        "ha_pin": ha_pin,
        "Token_Label": Token_Label,
        "SO_PIN": SO_PIN,
        "User_PIN": User_PIN
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object