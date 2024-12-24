import psycopg2
import requests
import os
# Hedef URL
ROOT_API_URL = 'http://127.0.0.1:8000/'

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
    return response.json()

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

def CSR_HSM_CRT_Request(csr_file_path,CompanyName,pin,slot_id,ca_crt_name,ca_key_name):
    with open(csr_file_path, "r") as dosya:
        print("Dosya adı:", dosya.name)
    URL = ROOT_API_URL + "CSR_HSM_CRT/"
    Name_CRT = CompanyName +".csr"
    files = {
    'csr_file': (Name_CRT, open(csr_file_path, 'rb'), 'application/x-pem-file')
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


# Veritabanı bağlantısı kur
def Get_Obje_Postgresql(X):
    conn = psycopg2.connect(
        database="pki_gui_db",
        user="postgres",
        password="postgres",
        host="127.0.0.1",
        port="5432"
    )
    # Veritabanı bağlantısı üzerinde bir imleç oluştur
    cur = conn.cursor()
    # X = 13
    # SQL sorgusu
    sql_query = f'SELECT "KeyName", "Certificate_Name", "Country", "Company", "Common_Name", "Serial_Number" FROM public.app_certificate_info WHERE id = {X};'
    # Sorguyu çalıştır
    cur.execute(sql_query)
    # Veriyi al
    result = cur.fetchone()
    # Veriyi değişkenlere ata
    key_name, certificate_name, country, company, common_name, serial_number = result
    print(result)
    # Bağlantıları kapat
    cur.close()
    conn.close()
    # Değişkenleri kullan
    print(f"ID: {id}")
    print(f"KeyName: {key_name}")
    print(f"Certificate_Name: {certificate_name}")
    print(f"Country: {country}")
    print(f"Company: {company}")
    print(f"Common_Name: {common_name}")
    print(f"Serial_Number: {serial_number}")
    ID = 0
    pin = "1111"
    bit = 2048
    str_serial = str(serial_number)
    key_name_priv = "RSAKeyspriv"
    str_serial = str(serial_number)
    #csr_result = CSR_Request_HSM_Request(ID,pin,key_name_priv,country,company,company,common_name,str_serial)
    #print(csr_result)
    csr_file_path = "D:\\Projects\\HSM\\PKI-HSM-Python\\PKI-APP\\app\\CSR\\"+common_name+"\\"+common_name+".csr"
    ca_crt_name = "Procenne"
    ca_key_name = "Procennepriv"
    CSR_HSM_CRT_Request(csr_file_path,company,pin,ID,ca_crt_name,ca_key_name)
    # CRT_result = CSR_HSM_CRT_Request(csr_file_path,company,pin,ID,ca_crt_name,ca_key_name)
    # data_crt = CRT_result['Message: ']
    # # Çalıştığı dizini al
    # current_directory = os.getcwd()
    # cert_folder_path = os.path.join(current_directory, "Certificate")
    # if not os.path.exists(cert_folder_path):
    #     os.makedirs(cert_folder_path)
    # crt_name = common_name + ".crt"
    # file_path = os.path.join(cert_folder_path, crt_name)
    # print(data_crt)
    # with open(file_path, "w") as file:
    #     file.write(data_crt)



    # if result['message:'] == Message_Key:
    #     str_serial = str(serial_number)
    #     csr_result = CSR_Request_HSM_Request(ID,pin,key_name_priv,country,company,company,common_name,str_serial)
    #     print(csr_result)
    #     csr_file_path = "D:\\Projects\\HSM\\PKI-HSM-Python\\PKI-APP\\app\\CSR\\"+common_name+"\\"+common_name+".csr"
    #     ca_crt_name = "Procenne"
    #     ca_key_name = "Procennepriv"
    #     CRT_result = CSR_HSM_CRT_Request(csr_file_path,company,pin,ID,ca_crt_name,ca_key_name)
    #     print(CRT_result)
    # else:
    #     print(result)

for i in range(15000):
    X = i + 1
    Get_Obje_Postgresql(X)


# ygqbGfdFA
# KKtXpTVkn