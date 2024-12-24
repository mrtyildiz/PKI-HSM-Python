import socket
import threading

# Hedef sunucu ve port bilgileri
hedef_ip = '192.168.1.61'
hedef_port = 9089

# Yönlendirme sunucu ve port bilgileri
yönlendirme_ip = '127.0.0.1'
yönlendirme_port = 9089

def istemci_oku(istemci_socket):
    while True:
        veri = istemci_socket.recv(1024)
        if not veri:
            break
        hedef_socket.send(veri)

def hedef_oku(hedef_socket):
    while True:
        veri = hedef_socket.recv(1024)
        if not veri:
            break
        istemci_socket.send(veri)

# Yönlendirme sunucu soketi oluşturma
yönlendirme_sunucu = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
yönlendirme_sunucu.bind((yönlendirme_ip, yönlendirme_port))
yönlendirme_sunucu.listen(5)

print(f"[+] Yönlendirme sunucu {yönlendirme_ip}:{yönlendirme_port} dinleniyor...")

while True:
    istemci_socket, istemci_addr = yönlendirme_sunucu.accept()
    print(f"[+] İstemci bağlandı: {istemci_addr[0]}:{istemci_addr[1]}")

    hedef_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hedef_socket.connect((hedef_ip, hedef_port))

    # İstemci ve hedef için iki ayrı thread oluşturma
    istemci_thread = threading.Thread(target=istemci_oku, args=(istemci_socket,))
    hedef_thread = threading.Thread(target=hedef_oku, args=(hedef_socket,))

    istemci_thread.start()
    hedef_thread.start()
