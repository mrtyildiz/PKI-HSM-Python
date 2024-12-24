FROM python:latest
RUN apt install -y && apt update -y && apt upgrade -y && apt dist-upgrade -y
RUN apt install -y nano
RUN mkdir -p /opt/procrypt/km3000/config
COPY config /opt/procrypt/km3000/config/
COPY libprocryptoki.so /lib64/
COPY libhsm.so /lib64/
COPY libhsm.so /lib/
COPY requirements.txt /app/
ENV PYKCS11LIB /lib64/libprocryptoki.so
RUN apt-get install gnutls-bin -y
RUN apt install swig -y
RUN apt install opensc -y
RUN pip3 install -r /app/requirements.txt
WORKDIR /app/