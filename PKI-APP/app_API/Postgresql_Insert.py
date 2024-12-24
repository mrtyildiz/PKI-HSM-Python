import psycopg2

# # Örnek sertifika verileri
# common_name = "example.com"
# certificate_data = "-----BEGIN CERTIFICATE-----\nYourCertificateDataHere\n-----END CERTIFICATE-----"
# private_key_data = "-----BEGIN PRIVATE KEY-----\nYourPrivateKeyDataHere\n-----END PRIVATE KEY-----"
def Insert_Certificate(common_name, certificate_data, private_key_data):
    # PostgreSQL veritabanına bağlan
    connection = psycopg2.connect(
        host="172.16.0.2",
        database="postgres",
        user="postgres",
        password="postgres"
    )

    # Veritabanı bağlantısını oluştur
    cursor = connection.cursor()
    # Veritabanına veriyi ekle
    cursor.execute(
        "INSERT INTO certificates (common_name, certificate_data, private_key_data) VALUES (%s, %s, %s)",
        (common_name, certificate_data, private_key_data)
    )
    # Değişiklikleri kaydet
    connection.commit()
    # Veritabanı bağlantısını kapat
    cursor.close()
    connection.close()
