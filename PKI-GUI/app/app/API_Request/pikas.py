import pika
import json

connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq', credentials=pika.PlainCredentials('myuser', 'mypassword')))
#connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
channel = connection.channel()
channel.queue_declare(queue='apiQuery', durable=True)
#channel.queue_declare(queue='apiQuery')

def callback(ch, method, properties, body):
    data = json.loads(body)
    print("Received JSON data:", data)

channel.basic_consume(queue='apiQuery', on_message_callback=callback, auto_ack=True)

print('Waiting for JSON data. To exit, press Ctrl+C')
channel.start_consuming()
