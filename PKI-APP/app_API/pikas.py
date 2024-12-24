import pika
import json
import requests
import os
from Slot_Intialized_Merge import Token_Create
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
    # result = Main_Request(Endpoint, request_data)
    # print(result)

    # İstek verilerini işle (örneğin, gerçek bir API çağrısı yap)
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
    URL = ROOT_API_URL + "HSM_Pool_Active/"
    # İsteği gönderin
    ##print(data)
    response = requests.post(URL, json=data)
    return response.json()

def FindID(data):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def RSA_Create_Request(data):
    URL = ROOT_API_URL + "RSACreate/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def CA_Create_Request(data):
    URL = ROOT_API_URL + "CARequest/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Danger_Token_Slot_Request(data):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Certificate_Info_Request(data):
    URL = ROOT_API_URL + "Certificate_Info/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Certificate_Load_Request(data):
    URL = ROOT_API_URL + "LoadCertificate/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def CSR_Request_HSM_Request(data):
    URL = ROOT_API_URL + "CSR_Request_HSM/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def CSR_HSM_CRT_Request(data):
    URL = ROOT_API_URL + "CSR_HSM_CRT/"
    # İsteği gönderin
    files_path = data['files']
    files = files_path[4:]
    print(files)
    file = files.split('/')
    filename = file[-1]
    print(filename)
    files = {
    'csr_file': (filename, open(files_path, 'rb'), 'application/x-pem-file')
    }
    if "files" in data:
        del data["files"]
    #print(data)
    session = requests.Session()
    response = session.post(URL, files=files, data=data)
    return response.json()

def CertificateExport_Request(data):
    URL = ROOT_API_URL + "CertificateExport/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def PublicKeyExport_Request(data):
    URL = ROOT_API_URL + "PublicKeyExport/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def AES_Create_Request(data):
    URL = ROOT_API_URL + "AESCreate/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Obje_Remove_Request(data):
    print(data)
    URL = ROOT_API_URL + "Obje_Remove/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Check_Token_Slot_Request(data):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Users_Obje_all(data):
    URL = ROOT_API_URL + "User_Info_All/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()


def TokenIDFind(data):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def User_Create_Request(data):
    URL = ROOT_API_URL + "UserCreate/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Users_Obje_Delete(data):
    URL = ROOT_API_URL + "UserObjeRemove/"
    # İsteği gönderin
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Certificate_ALL(data):
    URL = ROOT_API_URL + "Certificate_Info_All/"
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Obje_Find_URL(data):
    URL = ROOT_API_URL + "Obje_Find_URL/"
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()
def Find_Obje(data):
    URL = ROOT_API_URL + "Label_Obje_Find/"
    #print(data)
    response = requests.post(URL, json=data)
    return response.json()
def Slot_PIN_ENC_DEC(data):
    URL = ROOT_API_URL + "Slot_Find_PIN/"
    #print(data)
    response = requests.post(URL, json=data)

    return response.json()
def UserVerify_Rabbit(data):
    URL = ROOT_API_URL + "UserVerify/"
    #print(data)
    response = requests.post(URL, json=data)

    return response.json()

def FileEncrypt(data):
    URL = ROOT_API_URL + "FileEncPYHSM/"
    #print(data)
    response = requests.post(URL, json=data)

    return response.json()

def FileDecrypt(data):
    URL = ROOT_API_URL + "FileDecPYHSM/"
    #print(data)
    response = requests.post(URL, json=data)

    return response.json()


def CA_Create_Request_2(data):
    URL = ROOT_API_URL + "CARequestNew/"
    #print(data)
    response = requests.post(URL, json=data)

    return response.json() 

def CSR_Create_New(data):
    URL = ROOT_API_URL + "CSR_Request_HSM_New/"
    #print(data)
    response = requests.post(URL, json=data)
    print(response)
    return response.json() 

def ECCreate(data):
    URL = ROOT_API_URL + "EC_Create/"
    #print(data)
    response = requests.post(URL, json=data)

    return response.json()

def CRT_Verifty_Request(data):
    URL = ROOT_API_URL + "CRT_Verifty_Request/"
    #print(data)
    response = requests.post(URL, json=data)

    return response.json()

def CRT_Key_Verifty_Request(data):
    URL = ROOT_API_URL + "verify_certificate_key/"
    #print(data)
    response = requests.post(URL, json=data)

    return response.json()

def HSM_Tokens_Request(data):
    URL = ROOT_API_URL + "HSM_Tokens/"
    print(data)

    response = requests.post(URL)

    return response.json()

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
        'CSR_Request_HSM_New/' : CSR_Create_New,
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
