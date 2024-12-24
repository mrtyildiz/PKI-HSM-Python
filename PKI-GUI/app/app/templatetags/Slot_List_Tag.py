from django import template
import hashlib
from .API_Request import * 
import requests
import os
# Hedef URL
import pika
import uuid
import json
import os


Rabbit_Host = os.environ.get("Rabbit_Host")
RabbitUser = os.environ.get("RabbitUser")
RabbitPassword = os.environ.get("RabbitPassword")

class APIClient:
    def __init__(self, host, username, password):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host,
                credentials=pika.PlainCredentials(username, password)
            )
        )
        self.channel = self.connection.channel()

        result = self.channel.queue_declare(queue='', exclusive=True)
        self.callback_queue = result.method.queue

        self.channel.basic_consume(queue=self.callback_queue, on_message_callback=self.on_response, auto_ack=True)

    def on_response(self, ch, method, properties, body):
        if self.corr_id == properties.correlation_id:
            self.response = body

    def call_api(self, request_data):
        self.response = None
        self.corr_id = str(uuid.uuid4())
        self.channel.basic_publish(
            exchange='',
            routing_key='api_queue',
            properties=pika.BasicProperties(
                reply_to=self.callback_queue,
                correlation_id=self.corr_id,
            ),
            body=json.dumps(request_data)
        )
        while self.response is None:
            self.connection.process_data_events()
        return self.response

register=template.Library()

def calculate_md5(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode("utf-8"))
    return md5_hash.hexdigest()

@register.simple_tag
def slot_PIN_MD5(Slot_PIN):
    MD5Sum = calculate_md5(Slot_PIN)
    return MD5Sum

def Check_Token_Slot_Request(Token):
    data = {
        "Endpoint":"Check_Token_Slot/",
        "TokenName": Token
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    Return_Message = json_object['Message: ']
    if Return_Message == 'Token not found':
        healthy = "unhealthy"
    else:
        healthy = "healthy"
    return healthy


@register.simple_tag
def TokenCheckSlot(Token):
    Check = Check_Token_Slot_Request(Token)
    return Check

def Danger_Token_Slot_Request(Token):
    data = {
        "Endpoint":"Check_Token_Slot/",
        "TokenName": Token
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    Return_Message = json_object['Message: ']
    if Return_Message == 'Token not found':
        healthy = "danger"
    else:
        healthy = "primary"
    return healthy


@register.simple_tag
def TokenDangerSlot(Token):
    Check = Danger_Token_Slot_Request(Token)
    return Check
