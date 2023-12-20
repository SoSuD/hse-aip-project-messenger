import threading

from main import MessengerClient

client1 = MessengerClient('ezl0l', '1234567890')
print(client1.auth())

events_thread1 = threading.Thread(target=client1.events_handler,
                                  daemon=True)
events_thread1.start()

while True:
    client1.send_message(8, input('Message: '))
