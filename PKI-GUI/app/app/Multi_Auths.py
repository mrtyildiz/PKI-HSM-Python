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

  # SMTP sunucusuna bağlanma
  # with smtplib.SMTP(smtp_server, smtp_port) as server:
  #     # Sunucuya bağlandıktan sonra HELO komutunu gönder
  #     server.ehlo()

  #     # E-posta gönderme işlemi
  #     server.sendmail(sender_email, recipient_email, message.as_string())

  # print('E-posta gönderildi.')
  print("mailcode: "+str(mail_code))
  return mail_code




# def Send_Mail(sender,receiver,message):
#     with smtplib.SMTP("sandbox.smtp.mailtrap.io", 2525) as server:
#         server.login("5d26c5b4f47d8a", "26866cfe03dd40")
#         server.sendmail(sender, receiver, message)
# def Mail_numberCreate():
#    mail_code = str(randint(100000, 999999))
#    print(mail_code)
#    sender = "Private Person <from@example.com>"
#    receiver = "A Test User <to@example.com>"
#    message = f"""\
#     Subject: Hi Mailtrap
#     To: {receiver}
#     From: {sender}
#     The Mail verifty {mail_code}."""
#    Send_Mail(sender,receiver,message)
#    return mail_code
def Send_SMS(number):
  sms_code = str(randint(100000, 999999))

  # account_sid = 'AC2054ecea6c83305a3cd0ba331f11fe14'
  # auth_token = '73f6846b95d227b0a325647ff8ace765'
  # client = Client(account_sid, auth_token)

  # message = client.messages.create(
  #     messaging_service_sid='MG2ef369dc0a0d11690d38254238685560',
  #   body=f'Procenne PKI verification number is : {sms_code}',
  #   to=f'+90{number}'
  # )

  print(sms_code)
  return sms_code
