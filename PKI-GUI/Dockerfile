FROM python:latest
RUN apt install -y && apt update -y && apt upgrade -y && apt dist-upgrade -y
RUN apt install -y nano
RUN mkdir -p /app/
COPY requirements.txt /app/
RUN pip3 install -r /app/requirements.txt
WORKDIR /app/