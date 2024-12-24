import socket
import ssl

# İstemci soketi oluştur
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 8080))

# Sunucu sertifikası (PKI tarafından sağlanır)
server_certfile = 'certificate.pem'

# SSL/TLS bağlantısı için istemci soketini güvenli hale getir
client_ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
client_ssl_context.load_verify_locations(cafile=server_certfile)
client_ssl_socket = client_ssl_context.wrap_socket(client_socket, server_hostname='localhost')

# Veri alışverişi veya işlem yapma
client_ssl_socket.send("Merhaba, SSL/TLS ile güvendeyim!".encode('utf-8'))
response = client_ssl_socket.recv(1024)
print("Sunucu cevabı:", response.decode('utf-8'))

client_ssl_socket.close()
