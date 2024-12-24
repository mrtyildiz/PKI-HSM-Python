import os
import json
import re
from datetime import datetime

def extract_date_from_filename(filename):
    # Regex kullanarak tarih ve saat bilgisini ayıkla
    match = re.search(r'(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})', filename)
    if match:
        date_str = match.group(1)
        # Ayıklanan string'i datetime objesine dönüştür ve formatla
        date_obj = datetime.strptime(date_str, '%Y-%m-%d_%H-%M-%S')
        return date_obj.strftime('%Y-%m-%d %H:%M:%S')
    return None

def get_file_info():
    directory = '/opt/BackupLog/'  # Dizin yolu
    file_info_list = []
    for filename in os.listdir(directory):
        if filename.endswith(".csv") or filename.endswith(".csv.enc"):
            file_path = os.path.join(directory, filename)
            creation_time = os.path.getctime(file_path)
            creation_date = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
            extracted_date = extract_date_from_filename(filename)
            file_info = {
                'file_name': filename,
                'Last_date': creation_date,
                'First_date': extracted_date
            }
            file_info_list.append(file_info)
    return file_info_list


# file_info_list = get_file_info()

# # JSON formatında dosya bilgilerini yazdır
# json_output = json.dumps(file_info_list, indent=4)
# print(json_output)
