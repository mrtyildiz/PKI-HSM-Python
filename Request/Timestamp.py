import os
import datetime

def get_file_timestamps(file_path):
    # Dosyanın oluşturulma, değiştirilme ve erişim zaman damgalarını al
    creation_time = os.path.getctime(file_path)
    modification_time = os.path.getmtime(file_path)
    access_time = os.path.getatime(file_path)

    # Zaman damgalarını okunabilir formata çevir
    creation_time_str = datetime.datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
    modification_time_str = datetime.datetime.fromtimestamp(modification_time).strftime('%Y-%m-%d %H:%M:%S')
    access_time_str = datetime.datetime.fromtimestamp(access_time).strftime('%Y-%m-%d %H:%M:%S')

    return {
        "creation_time": creation_time,
        "modification_time": modification_time,
        "access_time": access_time,
        "creation_time_str": creation_time_str,
        "modification_time_str": modification_time_str,
        "access_time_str": access_time_str
    }

# Örnek dosya yolu
file_path = '/opt/BackupLog/logs_backup_2023-11-20_17-14-33.json.enc'

# Dosyanın zaman damgalarını al
timestamps = get_file_timestamps(file_path)

# Sonuçları yazdır
print("Dosyanın Oluşturulma Zamanı:", timestamps["creation_time_str"])
print("Dosyanın Değiştirilme Zamanı:", timestamps["modification_time_str"])
print("Dosyanın Erişim Zamanı:", timestamps["access_time_str"])
