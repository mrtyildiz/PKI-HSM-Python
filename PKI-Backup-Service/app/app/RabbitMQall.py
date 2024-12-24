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


def Slot_PIN_ENC_DEC(Action,PIN_Str):
    Real_API_Key = os.environ.get('API_Slot')
    data = {
        "Endpoint":"Slot_Find_PIN/",
        "API_Key": Real_API_Key,
        "Action": Action,
        "Strings_Slot_PIN": PIN_Str
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object


def FindID(Token):
    data = {
        "Endpoint":"Check_Token_Slot/",
        "TokenName": Token
    }
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object

def FileEncrypt(ID,PIN,KeyName,FileName):
    data = {
        "Endpoint":"FileEncPYHSM/",
        "ID": ID,
        "PIN": PIN,
        "init_vector": "2r4AlGJ7VsFS0AS1Dw4FCA==",
        "KName": KeyName,
        "FNamePath": FileName
    }
    # Rabbitmq İsteği gönderin
    api_client = APIClient(Rabbit_Host, RabbitUser, RabbitPassword)
    response = api_client.call_api(data)
    api_client.connection.close()
    json_string = response.decode('utf-8')
    json_object = json.loads(json_string)
    return json_object
