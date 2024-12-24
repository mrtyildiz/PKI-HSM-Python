import json
from datetime import datetime

# Lisans bilgilerini tanımla
license_info = {"license_key": "12345-abcde-67890-fghij","issued_to": "Müşteri Adı veya Şirket","issued_date": datetime(2024, 1, 1, 9, 0).isoformat(),"expiry_date": datetime(2025, 1, 1, 17, 0).isoformat(),"license_type": "Pro","additional_info": {"contact_email": "musteri@example.com","max_users": 50}}

# Lisans bilgilerini bir JSON dosyasına yaz
file_path = 'my_license_info.json'  # İstediğiniz dosya yolunu buraya yazabilirsiniz
with open(file_path, 'w') as file:
    json.dump(license_info, file, indent=4)
