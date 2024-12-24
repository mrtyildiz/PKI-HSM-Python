import pika
import json
import requests

ROOT_API_URL = "http://localhost:8000/"
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
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def FindID(data):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def RSA_Create_Request(data):
    URL = ROOT_API_URL + "RSACreate/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def CA_Create_Request(data):
    URL = ROOT_API_URL + "CARequest/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Danger_Token_Slot_Request(data):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Certificate_Info_Request(data):
    URL = ROOT_API_URL + "Certificate_Info/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Certificate_Load_Request(data):
    URL = ROOT_API_URL + "LoadCertificate/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def CSR_Request_HSM_Request(data):
    URL = ROOT_API_URL + "CSR_Request_HSM/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def CSR_HSM_CRT_Request(data):
    URL = ROOT_API_URL + "CSR_HSM_CRT/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def CertificateExport_Request(data):
    URL = ROOT_API_URL + "CertificateExport/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def PublicKeyExport_Request(data):
    URL = ROOT_API_URL + "PublicKeyExport/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def AES_Create_Request(data):
    URL = ROOT_API_URL + "AESCreate/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Obje_Remove_Request(data):
    URL = ROOT_API_URL + "Obje_Remove/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Check_Token_Slot_Request(data):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Users_Obje_all(data):
    URL = ROOT_API_URL + "User_Info_All/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()


def TokenIDFind(data):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def User_Create_Request(data):
    URL = ROOT_API_URL + "UserCreate/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

def Users_Obje_Delete(data):
    URL = ROOT_API_URL + "UserObjeRemove/"
    # İsteği gönderin
    print(data)
    response = requests.post(URL, json=data)
    return response.json()

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

    }
    
    selected_function = switch_dict.get(case, default_function)
    return selected_function(data)



### Sistem başlatıldı.
connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        'rabbitmq',
        credentials=pika.PlainCredentials('myuser', 'mypassword')
    )
)
channel = connection.channel()

channel.queue_declare(queue='api_queue')
channel.basic_consume(queue='api_queue', on_message_callback=on_request)

print("API Sunucusu Başlatıldı. İstekleri Dinliyor...")
channel.start_consuming()
