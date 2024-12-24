FROM python
RUN apt install -y && apt update -y && apt upgrade -y 
RUN mkdir -p /app
COPY requirements.txt /app/
WORKDIR /app/
RUN pip3 install -r requirements.txt