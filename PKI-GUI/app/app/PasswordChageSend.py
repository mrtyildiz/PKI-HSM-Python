from random import randint
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import datetime
from datetime import datetime, timedelta

def calculate_minute_difference(date_string):
    # Şu anki tarihi al
    # Verilen string formatına uygun bir tarih ve saat objesi oluştur
    target_datetime = datetime.strptime(date_string, "%m %d %Y %H:%M")

    # Şu anki tarihi al
    current_time = datetime.now()

    # İki tarih arasındaki dakika farkını hesapla
    time_difference = current_time - target_datetime
    print(time_difference)
    minutes_difference = time_difference.total_seconds() / 60

    # Dakika farkının 60'dan büyük olup olmadığını kontrol et
    if minutes_difference > 60:
        return False
    else:
        return True

def encrypt(plaintext):
    # Sabit key ve IV
    key = b'G\xd1\t$vA\x10~\x18\x96\xd2\x94\xecr\xac\xf6\xf5\nj\x90\xfb\xcf|\xb0L\xea\xa5\xe9\xfb\x07\xfa\xeb'
    iv = b'\x16\x81W\xc6(V\xe2\xb8\x7f\xf1\xc8\xd5\xbb\x0f\x9b\x14'

    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Encrypt the plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Combine IV and ciphertext, then encode with base64
    encrypted_data = iv + ciphertext
    encrypted_data_base64 = urlsafe_b64encode(encrypted_data).decode()

    # Return the base64 encoded string
    return encrypted_data_base64
    

def decrypt(base64_ciphertext):

    # Decode base64
    encrypted_data = urlsafe_b64decode(base64_ciphertext.encode())

    # Extract IV and ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Sabit key
    key = b'G\xd1\t$vA\x10~\x18\x96\xd2\x94\xecr\xac\xf6\xf5\nj\x90\xfb\xcf|\xb0L\xea\xa5\xe9\xfb\x07\xfa\xeb'

    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Return the plaintext
    return plaintext

ROOT_URL_STR = "http://192.168.1.140:9000/"
def Mail_Password_Send(recipient_email,E_mail_ENC):
    # MailHog SMTP sunucusunun bilgileri
  smtp_server = '172.16.0.13'
  smtp_port = 1025
  sender_email = 'PasswordChange@procenne.com'
  subject = 'PasswordChange'
  # Zamanı istenen formatta yazdır
  now = datetime.now()

# Zaman formatını belirle
  time_format = "%m %d %Y %H:%M"

# Zamanı istenen formatta yazdır
  formatted_time = now.strftime(time_format)
  bytes_data = formatted_time.encode('utf-8')
  Data_Enc = encrypt(bytes_data)
  # E-posta oluşturma
  message = MIMEMultipart()
  message['From'] = sender_email
  message['To'] = recipient_email
  message['Subject'] = subject
  body = f'''Greetings,

You can use the link below to change your password.
{ROOT_URL_STR}PasswordChange/{E_mail_ENC}/{Data_Enc}/
For your information,
Yours sincerely.'''
  message.attach(MIMEText(body, 'plain'))


  with smtplib.SMTP(smtp_server, smtp_port) as server:
      # Sunucuya bağlandıktan sonra HELO komutunu gönder
      server.ehlo()

      # E-posta gönderme işlemi
      server.sendmail(sender_email, recipient_email, message.as_string())

  print('E-posta gönderildi.')
