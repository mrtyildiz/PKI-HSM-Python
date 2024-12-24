import os
import django
import schedule
import time
# Django projenizin ayar dosyasının yolu
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pki_gui.settings')
# Django'yı başlat
django.setup()
import subprocess
import datetime
from app.API_Request.RabbitMQall import *
from app.models import slotlist

from ftplib import FTP

from ftplib import FTP
import os

def upload_file(ftp, local_path, remote_filename):
    with open(local_path, 'rb') as local_file:
        ftp.storbinary(f'STOR {remote_filename}', local_file)
def FileUpload(filename):
    # FTP server credentials
    ftp_host = "172.16.0.12"
    ftp_user = "FTPAdmin"
    ftp_password = "1q2w3e4r5t*"

    # File to upload
    local_filename = f'/opt/BackupLog/{filename}'
    remote_filename = filename

    # Establish FTP connection
    ftp = FTP(ftp_host)
    ftp.login(user=ftp_user, passwd=ftp_password)

    # Change to the desired remote directory (optional)
    remote_directory = ""
    ftp.cwd(remote_directory)

    # Upload the file
    upload_file(ftp, local_filename, remote_filename)

    # Close FTP connection
    ftp.quit()

    print(f"{local_filename} has been successfully uploaded to {remote_directory}/{remote_filename}.")

def backup_logs_model():
    try:
        # Yedekleme dosyasının adı ve yolu
        backup_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        backup_file = f'logs_backup_{backup_time}.json'

        # dumpdata komutunu çalıştır
        command = f"python3 /app/manage.py dumpdata app.Logs > /opt/BackupLog/{backup_file}"
        subprocess.run(command, shell=True, check=True)

        print(f"Logs model backed up successfully: {backup_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
    except Exception as e:
        print(f"General error occurred: {e}")
    return backup_file
def restore_logs_model(backup_file):
    try:
        # loaddata komutunu çalıştır
        command = f"python3 /app/manage.py loaddata {backup_file}"
        subprocess.run(command, shell=True, check=True)
        print(f"Logs model restored successfully: {backup_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
    except Exception as e:
        print(f"General error occurred:: {e}")




def BackupFull(TokenName,KeyName):
    try:

        print("deneme")
        filename = backup_logs_model()
        Slot_Token = slotlist.objects.get(TokenName=TokenName)
        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,Slot_Token.UserPIN)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
        Slot_Info = FindID(TokenName)
        Token_ID = Slot_Info['Message: ']['slot_id']
        result = FileEncrypt(Token_ID,Token_PIN,KeyName,filename)
        print(result)
        if result == 'İşlem Başarılı':
            Root_Log = "/opt/BackupLog/"+str(filename)
            if os.path.exists(Root_Log):
                os.remove(Root_Log)

            else:
                pass
        File_Enc_Log = filename +".enc"
        FileUpload(File_Enc_Log)
        print(File_Enc_Log)
    except:
        pass
# TokenName = "PKI_Client"
# KeyName = "Log_File_Encrypt"
# BackupFull(TokenName,KeyName)

# schedule.every(60).minutes.do(lambda: BackupFull('PKI_Client', 'Log_File_Encrypt'))

# while True:
#     schedule.run_pending()
#     time.sleep(1)  # İşlemciyi yormamak için küçük bir bekleme ekleyebilirsiniz
