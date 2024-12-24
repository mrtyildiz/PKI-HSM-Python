# Docker taban imajını belirle
FROM python:3.9

# Gerekli Python paketini yükle
RUN pip install pyftpdlib
RUN python3 -m pip install python-ftp-server
# Çalışma dizinini ayarla
RUN mkdir -p /app/LogBackup/
WORKDIR /app
