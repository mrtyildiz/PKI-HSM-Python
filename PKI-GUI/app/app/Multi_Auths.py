#from twilio.rest import Client
from random import randint
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def Mail_numberCreate(recipient_email):
    # MailHog SMTP sunucusunun bilgileri
  smtp_server = '172.16.0.13'
  smtp_port = 1025
  sender_email = 'PKITwoFactor@procenne.com'
  subject = 'TwoFactor'
  

  # E-posta oluşturma
  message = MIMEMultipart()
  message['From'] = sender_email
  message['To'] = recipient_email
  message['Subject'] = subject
  mail_code = str(randint(100000, 999999))
  body = f'The postcode you can use in the Procenne PKI Application: {mail_code}'
  message.attach(MIMEText(body, 'plain'))
  print("mailcode: "+str(mail_code))
  return mail_code

def Send_SMS(number):
  sms_code = str(randint(100000, 999999))
  print(sms_code)
  return sms_code
