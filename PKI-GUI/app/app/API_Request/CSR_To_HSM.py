import requests
# Hedef URL
import os
ROOT_API_URL = os.environ.get("API_URL")

def CSR_HSM_CRT_Request(csr_file_path,crt_file_name,CompanyName,pin,slot_id,ca_crt_name,ca_key_name):
    with open(csr_file_path, "r") as dosya:
        print("Dosya adı:", dosya.name)
    URL = ROOT_API_URL + "CSR_HSM_CRT/"
    files = {
    'csr_file': (crt_file_name, open(csr_file_path, 'rb'), 'application/x-pem-file')
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