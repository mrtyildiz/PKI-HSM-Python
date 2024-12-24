import psycopg2
import requests
import os
ROOT_API_URL = os.environ.get("API_URL")


def Danger_Token_Slot_Request(Token):
    URL = ROOT_API_URL + "Check_Token_Slot/"
    data = {
        "TokenName": Token
    }
    # İsteği gönderin
    response = requests.post(URL, json=data)
    message = response.json()
    return message
