import os
import django
import time
import smtplib
import json
# Django projenizin ayar dosyasının yolu
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pki_gui.settings')
from datetime import datetime, date
from SendMail import Send_Mail
from app.API_Request.RabbitMQall import Slot_PIN_ENC_DEC,FindID,Certificate_ALL
# Django'yı başlat
django.setup()
from app.models import certificates, client_crt, slotlist

##### DB Bazlı işlem yapılması ####
def DB_Certificate_Check():
    CA_Certificate = certificates.objects.all()
    for Certificate in CA_Certificate:
        current_date = datetime.now().date()
        Day_Stay = (Certificate.Data_End - current_date).days
        if Day_Stay < 15:
            print("Mail Gönder")
            return Certificate.Certificate_Name
        else:
            print("Mail gönderme")
            result = "Not Found Mail"
            return result
    

def DB_Certificate_Client_Check():
    Client_Certificate = client_crt.objects.all()
    for Certificate in Client_Certificate:
        current_date = datetime.now().date()
        Day_Stay = (Certificate.Data_End - current_date).days
        if Day_Stay < 15:
            print("Mail Gönder")
            return Certificate.Certificate_Name
        else:
            print("Mail gönderme")
            result = "Not Found Mail"
            return result

def DB_Mail_Send_CA():
    CA_CRT = DB_Certificate_Check()
    if CA_CRT == 'Not Found Mail':
        pass
    else:
        sender = "Private Person <from@example.com>"
        receiver = "A Test User <to@example.com>"

        message = f"""\
        Subject: Hi Mailtrap
        To: {receiver}
        From: {sender}

        The certificate named {CA_CRT} has expired"""
        Send_Mail(sender,receiver,message)

def Client_CRT_Send_Mail():

    Client_CRT = DB_Certificate_Client_Check()
    if Client_CRT == 'Not Found Mail':
        pass
    else:
        print("Mail göndermede")
        sender = "Private Person <from@example.com>"
        receiver = "A Test User <to@example.com>"

        message = f"""\
        Subject: Hi Mailtrap
        To: {receiver}
        From: {sender}

        The certificate has expired"""
        Send_Mail(sender,receiver,message)

########


##### HSM Bazlı işlem yapılması ####
## Get Slot

All_Slot = slotlist.objects.all()

def get_all_certificate():
    Cert_Array = []
    for Slot in All_Slot:
        Slot_Name = Slot.TokenName
        Slot_PIN = Slot.UserPIN
        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,Slot_PIN)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
        Slot_Info = FindID(Slot_Name)
        Token_ID = Slot_Info['Message: ']['slot_id']
        Certificate_All = Certificate_ALL(str(Token_ID),Token_PIN)
        for i in range(len(Certificate_All)):
            Cert_Array.append(Certificate_All[i])

    for i in range(len(Cert_Array)):
        Last_Date = Cert_Array[i]['Last_Date']
        date_object = datetime.strptime(Last_Date, "%d/%m/%Y %H:%M:%S")
        current_date = datetime.now()
        days_difference = (date_object - current_date).days
        if days_difference > 15:
            pass
        else:
            print(Cert_Array[i]['Certificate_Name'])
            sender = "Private Person <from@example.com>"
            receiver = "A Test User <to@example.com>"

            message = f"""\
            Subject: Hi Mailtrap
            To: {receiver}
            From: {sender}

            The certificate has expired"""
            Send_Mail(sender,receiver,message)

get_all_certificate()
# sender = "Private Person <from@example.com>"
# receiver = "A Test User <to@example.com>"

# message = f"""\
# Subject: Certificate End Time
# To: {receiver}
# From: {sender}

# This is a test e-mail message."""

# with smtplib.SMTP("sandbox.smtp.mailtrap.io", 2525) as server:
#     server.login("5d26c5b4f47d8a", "26866cfe03dd40")
#     server.sendmail(sender, receiver, message)