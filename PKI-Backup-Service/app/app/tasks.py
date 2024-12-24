# app/tasks.py
from .models import Rules
from datetime import datetime, timedelta, timezone
from random import randint
import smtplib
from django.contrib.auth.models import User
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os

MailHostName = os.environ.get("MailHostName")
def check_date_range(given_time):
    # Şu anki tarihi ve saati al (UTC)
    current_time_utc = datetime.now(timezone.utc)
    # Bir saatlik bir timedelta oluştur
    one_hour_delta = timedelta(seconds=3610)
    # Bir saat önceki tarih ve saat'i hesapla
    one_hour_ago = current_time_utc - one_hour_delta
    # Verilen tarih, bir saat önceki tarih ve şu anki tarih arasında kontrol yap
    if one_hour_ago < given_time < current_time_utc:
        return True
    else:
        return False

def Mail_numberCreate(recipient_email, Cert_name):
    # MailHog SMTP sunucusunun bilgileri
  smtp_server = '172.16.0.13'
  smtp_port = 1025
  sender_email = 'PKI-Certificate-Warning@procenne.com'
  subject = 'Certificate-Warning'
  

  # E-posta oluşturma
  message = MIMEMultipart()
  message['From'] = sender_email
  message['To'] = recipient_email
  message['Subject'] = subject
  body = f'It is almost time to renew your { Cert_name } certificate'
  message.attach(MIMEText(body, 'plain'))

  # SMTP sunucusuna bağlanma
  with smtplib.SMTP(smtp_server, smtp_port) as server:
      # Sunucuya bağlandıktan sonra HELO komutunu gönder
      server.ehlo()
      # E-posta gönderme işlemi
      server.sendmail(sender_email, recipient_email, message.as_string())

  print('E-posta gönderildi.')
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def my_scheduled_task():
    Rules_Object = Rules.objects.all()
    for Rule in Rules_Object:
        result = check_date_range(Rule.Sending_Time)
        print(result)
        if result:
            print(Rule.Rules_Name)
            Cert_name = Rule.Certificate_Name
            email = User.objects.filter(username=Rule.Sending_Person).values_list('email', flat=True).first()
            Mail_numberCreate(email, Cert_name)
        else:
            pass
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"Scheduled task executed at {current_time}!")
    logging.info('Bu bir INFO logudur.')
