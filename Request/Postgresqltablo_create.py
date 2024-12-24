import psycopg2
import random
import string

for i in range(15000):
    # 6 haneli rasgele sayı üret
    print(i)
    six_digit_random_number = random.randint(100000000, 999999999)
    nine_alpha_random_string = ''.join(random.choices(string.ascii_letters, k=9))
    # Veritabanı bağlantısı
    conn = psycopg2.connect(
        database="pki_gui_db",
        user="postgres",
        password="postgres",
        host="192.168.1.140",
        port="5432"
    )
    # Veritabanı bağlantısı üzerinden bir işlem oluştur
    cur = conn.cursor()
    # Eklenecek veriler
    key_name = nine_alpha_random_string
    certificate_name = nine_alpha_random_string
    country = "TR"
    company = nine_alpha_random_string
    common_name = nine_alpha_random_string
    serial_number = six_digit_random_number

    # SQL sorgusu oluştur
    sql = """INSERT INTO public.app_certificate_info ("KeyName", "Certificate_Name", "Country", "Company", "Common_Name", "Serial_Number") VALUES (%s, %s, %s, %s, %s, %s);"""

    # Verileri ekleyin
    cur.execute(sql, (key_name, certificate_name, country, company, common_name, serial_number))
    # Değişiklikleri kaydet
    conn.commit()
    # Veritabanı bağlantısını kapat
    conn.close()
