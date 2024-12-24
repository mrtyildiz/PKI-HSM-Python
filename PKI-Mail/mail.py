import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# MailHog SMTP sunucusunun bilgileri
smtp_server = 'localhost'
smtp_port = 1025
sender_email = 'deneme3@procenne.com'
recipient_email = 'yusuf@procenne.com'
subject = 'Test subject'
body = 'Test mail body'

# E-posta oluşturma
message = MIMEMultipart()
message['From'] = sender_email
message['To'] = recipient_email
message['Subject'] = subject
message.attach(MIMEText(body, 'plain'))

# SMTP sunucusuna bağlanma
with smtplib.SMTP(smtp_server, smtp_port) as server:
    # Sunucuya bağlandıktan sonra HELO komutunu gönder
    server.ehlo()

    # E-posta gönderme işlemi
    server.sendmail(sender_email, recipient_email, message.as_string())

print('E-posta gönderildi.')
