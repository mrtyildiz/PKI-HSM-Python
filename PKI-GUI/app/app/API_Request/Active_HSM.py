import requests
import os
ROOT_API_URL = os.environ.get("API_URL")

def Active_HSM_Request(IP_Address,Port_Address):
    URL = ROOT_API_URL + "HSM_Pool_Active/"
    data = {
        "IP_Address": IP_Address,
        "Port_Address": Port_Address
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    return response.json()
