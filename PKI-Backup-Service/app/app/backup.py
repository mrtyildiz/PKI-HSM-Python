import datetime
import subprocess
from ftplib import FTP
import os
from .RabbitMQall import *
from .models import slotlist
from django.db import connection
from datetime import datetime
from datetime import timedelta
from django.utils import timezone
from .models import Logs, Logs_Bak

import csv
from django.conf import settings
import glob

def find_csv_files():
    directory = '/opt/BackupLog/'
    """Belirtilen dizindeki tüm .csv dosyalarını bulur."""
    # Dizindeki tüm .csv dosyalarının yolunu al
    csv_files = glob.glob(os.path.join(directory, '*.csv'))
    return csv_files

Postgresql_DB = os.environ.get("Postgresql_DB")
Postgresql_User = os.environ.get("Postgresql_User")
Postgresql_IP = os.environ.get("Postgresql_IP")
Postgresql_Password = os.environ.get("Postgresql_Password")
table_name = "app_logs_bak"

def get_file_size_in_mb(file_path):
    """Belirtilen dosyanın boyutunu MB cinsinden döndürür."""
    if os.path.exists(file_path):
        file_size_bytes = os.path.getsize(file_path)
        file_size_mb = file_size_bytes / (1024 * 1024)  # Bytes to MB
        #file_size_mb = file_size_bytes / (1 * 1)  # Bytes to MB
        return file_size_mb
    else:
        return None

def is_file_larger_than_10mb(file_path):
    """Belirtilen dosyanın 10 MB'dan büyük olup olmadığını kontrol eder."""
    file_size_mb = get_file_size_in_mb(file_path)
    if file_size_mb is not None:
        return file_size_mb > 1
    else:
        return False

# from datetime import datetime, timedelta
from app.models import Logs
def upload_file(ftp, local_path, remote_filename):
    with open(local_path, 'rb') as local_file:
        ftp.storbinary(f'STOR {remote_filename}', local_file)
def FileUpload(filename):
    ftp_host = os.environ.get("ftp_host")
    ftp_user = os.environ.get("ftp_user")
    ftp_password = os.environ.get("ftp_password")
    local_filename = f'/opt/BackupLog/{filename}'
    remote_filename = filename
    ftp = FTP(ftp_host)
    ftp.login(user=ftp_user, passwd=ftp_password)
    remote_directory = ""
    ftp.cwd(remote_directory)
    upload_file(ftp, local_filename, remote_filename)
    ftp.quit()

def BackupFull():
    TokenName = os.environ.get("TokenName")
    KeyName = os.environ.get("KeyName")
    
    try:

        filename = backup_specific_table_postgresql()
        
        if not filename:
            print("not file")
        else:
            print(f'Filename = {filename}')
            Slot_Token = slotlist.objects.get(TokenName=TokenName)
            Action = "Decrypt"
            result = Slot_PIN_ENC_DEC(Action,Slot_Token.UserPIN)
            json_string = json.dumps(result)
            loaded_data = json.loads(json_string)
            Token_PIN = loaded_data['Message:']['Decrypt Data: ']
            Slot_Info = FindID(TokenName)
            Token_ID = Slot_Info['Message: ']['slot_id']
            result = FileEncrypt(Token_ID,Token_PIN,KeyName,filename)
            print(result['Message:'])
            #print(result)
            if result['Message:'] == 'İşlem Başarılı':
                Root_Log = "/opt/BackupLog/"+str(filename)

                # if os.path.exists(Root_Log):
                #     pass
                if os.path.exists(Root_Log):
                    os.remove(Root_Log)
                    

                else:
                    pass
            File_Enc_Log = filename +".enc"
            FileUpload(File_Enc_Log)
    except:
        print("hata nedir")

def Bak_up_to_table():
    try:
        # Şu anki zamandan bir saat öncesini hesapla
        one_hour_ago = timezone.now() - timedelta(hours=1)

        # Son bir saatte oluşturulan Logs kayıtlarını al
        recent_logs = Logs.objects.filter(created_at__gt=one_hour_ago)

        # Logs_Bak modeline yeni kayıtlar ekle
        for log in recent_logs:
            Logs_Bak.objects.create(
                id = log.id,
                MultiTenantName=log.MultiTenantName,
                Log_Sensitives=log.Log_Sensitives,
                created_by=log.created_by,
                Log_Process=log.Log_Process,
                created_at=log.created_at,
                Description=log.Description
            )

     #   print("Son bir saatlik veri Logs_Bak tablosuna eklendi.")

    except Exception as e:
        print(f"Hata: {e}")

    # Fonksiyonun bir şey döndürmesine gerek yok

def truncate_table():
    try:
        # Logs_Bak modelinin tüm kayıtlarını sil
        Logs_Bak.objects.all().delete()

        #print("Logs_Bak tablosu tamamen temizlendi.")

    except Exception as e:
        print(f"Hata: {e}")
    
def check_id_in_csv(csv_file_path, id_to_check):
    """CSV dosyasında belirli bir ID'nin olup olmadığını kontrol eder."""
    id_to_check = str(id_to_check)  # ID'yi string'e dönüştür
    try:
        with open(csv_file_path, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Başlık satırını atla
            for row in reader:
                if row[0] == id_to_check:  # ID'nin bulunduğu sütun varsayılan olarak ilk sütundur
                    return True
        return False
    except FileNotFoundError:
        print(f"Dosya bulunamadı: {csv_file_path}")
        return False
  
def export_table_to_csv():
    csv_files = find_csv_files()
    print(len(csv_files))
    if len(csv_files) == 0:
        backup_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        backup_file = f'/opt/BackupLog/logs_backup_{backup_time}.csv'
        backup_file_name = f'logs_backup_{backup_time}.csv'
        try:
            # Logs_Bak modelinden tüm verileri al
            logs_bak_records = Logs_Bak.objects.all().values()

            # CSV dosyasını oluştur ve verileri yaz
            with open(backup_file, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file)
                # Başlık satırlarını yaz
                writer.writerow([field for field in logs_bak_records[0]])
                # Her kaydı CSV dosyasına yaz
                for record in logs_bak_records:
                    writer.writerow([record[field] for field in record])

            print(f"Logs_Bak tablosu {backup_file} dosyasına başarıyla dışa aktarıldı.")

        except Exception as e:
            print(f"Hata: {e}")

        return False
    if len(csv_files) == 1:
        files_csv_name = csv_files[0]
        logs_bak_records = Logs_Bak.objects.all().values()
        log_range_len = len(logs_bak_records)
        for i in range(log_range_len):
            logs_id = logs_bak_records[i]['id']
            result_csv = check_id_in_csv(files_csv_name, logs_id)
            if result_csv:
                print("çalısmadı")
            else:
                try:
                    # Belirli bir ID'ye sahip kaydı al
                    record = Logs_Bak.objects.get(id=logs_id)

                    # CSV dosyasını aç ve veriyi ekle
                    with open(files_csv_name, 'a', newline='', encoding='utf-8') as file:
                        writer = csv.writer(file)
                        # Kaydı CSV dosyasına yaz
                        print("Burada")
                        writer.writerow([getattr(record, field.name) for field in Logs_Bak._meta.fields])

                except Logs_Bak.DoesNotExist:
                    print(f"ID'si {logs_id} olan kayıt bulunamadı.")
        # result_mb = is_file_larger_than_10mb(files_csv_name)
        # file_name_array = result_mb.split('/')

        return files_csv_name

    else:
        return False

def get_row_count():
    try:
        # Logs_Bak modelindeki toplam kayıt sayısını bul
        row_count = Logs_Bak.objects.count()
        #print(f"Logs_Bak tablosundaki satır sayısı: {row_count}")

        return row_count

    except Exception as e:
        print(f"Hata: {e}")
        return None

def backup_specific_table_postgresql():

    ### Tabloyu Temizle
    truncate_table()
    ### Son bir saat içerisinde olan logları al
    Bak_up_to_table()
    #### Tablo içerisindeki veri sayısını kontrol et
    result = export_table_to_csv()
    print(result)
    if result:
        result_filename = result.split('/')
        filenames = result_filename[-1]
        result_mb = is_file_larger_than_10mb(result)
        print(result_mb)
        if result_mb:
            print("10 mb büyük")
            return(filenames)
        else:
            print("10 mb küçük")
            return False
    else:
        return False
    # row_count = get_row_count()
    # if row_count == 0:
    #     print("ara")
    #     result = False
    # else:
    #     result = export_table_to_csv()
    #     print(result)
    # return result