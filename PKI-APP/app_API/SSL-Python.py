import socket
import ssl

# Sunucu soketi oluştur
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 8080))
server_socket.listen(5)

# Sunucu sertifikası ve özel anahtarı (PKI tarafından sağlanır)
server_certfile = 'certificate.pem'
server_keyfile = 'private_key.pem'

# SSL/TLS bağlantısı için sunucu soketini güvenli hale getir
server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
server_ssl_context.load_cert_chain(certfile=server_certfile, keyfile=server_keyfile)
server_ssl_socket = server_ssl_context.wrap_socket(server_socket, server_side=True)

print("Sunucu bekliyor...")

while True:
    client_socket, client_address = server_ssl_socket.accept()
    print(f"Gelen bağlantı: {client_address}")
    
    # Veri alışverişi veya işlem yapma
    data = client_socket.recv(1024)
    print("Alınan veri:", data.decode('utf-8'))
    
    client_socket.send("Merhaba, SSL/TLS ile güvendesiniz!".encode('utf-8'))
    client_socket.close()
