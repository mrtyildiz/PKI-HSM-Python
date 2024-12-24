import requests

url = 'http://192.168.1.140:8000/CRT_Verifty_Request/'


data = {
    'crt_file': 'Kripto.crt',
    'CACertificateName': 'KriptoCA',
    'pin': '1111',
    'slot_id': '0',
}

response = requests.post(url, data=data)

print(response.status_code)
print(response.json())  # Assuming the response is in JSON format
