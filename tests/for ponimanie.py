import base64
from main import MessengerClient
import dh

client = MessengerClient('ezl0l', '1234567890')

client.private_keys[30] = dh.generate_key()
print(client.private_keys[30])

print(client.private_keys[30].public_key().export_key(format='DER'))