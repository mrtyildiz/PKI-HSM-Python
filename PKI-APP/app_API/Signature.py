from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

# Dokümanın yolu
document_path = '/app/document.txt'

# Dokümanı okuyun
with open(document_path, 'rb') as document_file:
    document_data = document_file.read()

# Özel anahtarın ve genel anahtarın oluşturulması
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# Dokümanı imzala
hash_object = SHA256.new(data=document_data)
signature = pkcs1_15.new(private_key).sign(hash_object)

# İmzalı dokümanı kaydet
signed_document_path = '/app/signed_document.txt'
with open(signed_document_path, 'wb') as signed_document_file:
    signed_document_file.write(signature + document_data)

print("Doküman başarıyla imzalandı ve kaydedildi.")

# İmzayı doğrula
with open(signed_document_path, 'rb') as signed_document_file:
    signed_document_data = signed_document_file.read()

signature_length = private_key.size_in_bytes()
signature = signed_document_data[:signature_length]
signed_data = signed_document_data[signature_length:]

try:
    pkcs1_15.new(public_key).verify(SHA256.new(data=signed_data), signature)
    print("İmza doğrulandı.")
except (ValueError, TypeError):
    print("İmza doğrulanamadı.")
