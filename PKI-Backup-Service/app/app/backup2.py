import os
import subprocess
from datetime import datetime, timedelta
import psycopg2
from psycopg2 import sql # Django modelini içe aktarın ve uygun bir şekilde düzenleyin

Postgresql_DB = os.environ.get("Postgresql_DB")
Postgresql_User = os.environ.get("Postgresql_User")
Postgresql_IP = os.environ.get("Postgresql_IP")
Postgresql_Password = os.environ.get("Postgresql_Password")
table_name = "app_logs_bak"
#### app_logs_bak içerisini doldur
def Bak_up_to_table():
    try:

        # PostgreSQL veritabanına bağlanma
        conn = psycopg2.connect(
            dbname=Postgresql_DB,
            user=Postgresql_User,
            password=Postgresql_Password,
            host=Postgresql_IP,
            port=5432
        )

        # Veritabanı üzerinde bir imleç oluştur
        cur = conn.cursor()

        # Son bir saatlik veriyi ekleyen SQL sorgusu
        append_last_hour_data_query = sql.SQL("""
            INSERT INTO {} (id, "MultiTenantName", "Log_Sensitives", "Log_Process", created_at, "Description", created_by_id)
            SELECT id, "MultiTenantName", "Log_Sensitives", "Log_Process", created_at, "Description", created_by_id
            FROM app_logs
            WHERE created_at > current_timestamp - interval '1 hour'
        """).format(sql.Identifier(table_name))

        cur.execute(append_last_hour_data_query)
        conn.commit()

        print("Son bir saatlik veri eklendi.")

    except Exception as e:
        print("Hata:", e)

    finally:
        # Bağlantıyı kapat
        if cur:
            cur.close()
        if conn:
            conn.close()

#### app_logs_bak temizle
def truncate_table():
    try:

        # PostgreSQL veritabanına bağlanma
        conn = psycopg2.connect(
            dbname=Postgresql_DB,
            user=Postgresql_User,
            password=Postgresql_Password,
            host=Postgresql_IP,
            port=5432
        )
        
        # Veritabanı üzerinde bir imleç oluştur
        cur = conn.cursor()

        # TRUNCATE komutu ile tabloyu tamamen temizle
        truncate_table_query = sql.SQL("""
            TRUNCATE TABLE {} RESTART IDENTITY;
        """).format(sql.Identifier(table_name))

        cur.execute(truncate_table_query)
        conn.commit()

        print(f"{table_name} tablosu tamamen temizlendi.")

    except Exception as e:
        print("Hata:", e)

    finally:
        # Bağlantıyı kapat
        if cur:
            cur.close()
        if conn:
            conn.close()


def export_table_to_csv():
    backup_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_file = f'/opt/BackupLog/logs_backup_{backup_time}.csv'
    backup_file_name = f'logs_backup_{backup_time}.csv'

    try:
        # PostgreSQL veritabanına bağlanma
        conn = psycopg2.connect(
            dbname=Postgresql_DB,
            user=Postgresql_User,
            password=Postgresql_Password,
            host=Postgresql_IP,
            port=5432
        )

        # Veritabanı üzerinde bir imleç oluştur
        cur = conn.cursor()

        # Tabloyu CSV dosyasına dışa aktar
        export_to_csv_query = f"COPY (SELECT * FROM {table_name}) TO STDOUT WITH CSV HEADER"
        
        with open(backup_file, 'w', encoding='utf-8') as csv_file:
            cur.copy_expert(sql=export_to_csv_query, file=csv_file)

        print(f"{table_name} tablosu {backup_file} dosyasına başarıyla dışa aktarıldı.")

    except Exception as e:
        print("Hata:", e)

    finally:
        # Bağlantıyı kapat
        if cur:
            cur.close()
        if conn:
            conn.close()
    return backup_file_name


def get_row_count():
    try:
        # PostgreSQL bağlantı bilgileri


        # PostgreSQL veritabanına bağlanma
        conn = psycopg2.connect(
            dbname=Postgresql_DB,
            user=Postgresql_User,
            password=Postgresql_Password,
            host=Postgresql_IP,
            port=5432
        )

        # Veritabanı üzerinde bir imleç oluştur
        cur = conn.cursor()

        # Tablonun satır sayısını bul
        get_row_count_query = f"SELECT COUNT(*) FROM {table_name};"
        cur.execute(get_row_count_query)

        row_count = cur.fetchone()[0]
        print(f"{table_name} tablosundaki satır sayısı: {row_count}")

    except Exception as e:
        print("Hata:", e)

    finally:
        # Bağlantıyı kapat
        if cur:
            cur.close()
        if conn:
            conn.close()
    return row_count

def backup_specific_table_postgresql():

    ### Tabloyu Temizle
    truncate_table()
    ### Son bir saat içerisinde olan logları al
    Bak_up_to_table()
    #### Tablo içerisindeki veri sayısını kontrol et
    row_count = get_row_count()
    if row_count == 0:
        result = False
    else:
        result = export_table_to_csv()
    return result


a = backup_specific_table_postgresql()
print(a)
