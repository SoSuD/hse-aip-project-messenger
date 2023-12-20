import base64
import dataclasses
import hashlib
import typing

import requests
from Crypto import Random

import dh


class MessengerClient:
    @dataclasses.dataclass
    class Message:
        to_user_id: int
        raw_content: str
        encrypted_content: bytes
        iv: bytes

    def __init__(self, username: str, password: str, endpoint_url: str = 'http://127.0.0.1:5000/'):
        assert endpoint_url.endswith('/'), 'Endpoint URL must end with \'/\''

        self.username = username
        self.password = password
        self.endpoint_url = endpoint_url
        self.session = requests.sessions.Session()
        self.session.headers.update({
            'X-Client-ID': 'mobile.android'
        })

        self.private_keys = {}
        self.session_keys = {}

        self.messages_stack: typing.List[MessengerClient.Message] = []

        self.user = None

    def signup(self):
        response = self.session.post(
            self.endpoint_url + 'api/users/create',
            json={
                'username': self.username,
                'password': self.password,
                'system_id': 'test',
                'application_id': '00000000-0000-0000-0000-000000000000'
            }
        ).json()

        if 'access_token' in response:
            self.set_token(response['access_token'])
            self.user = response['user']

        return response

    def auth(self):
        response = self.session.post(
            self.endpoint_url + 'api/users/auth',
            json={
                'username': self.username,
                'password': self.password,
                'system_id': 'test',
                'application_id': '00000000-0000-0000-0000-000000000000'
            }
        ).json()

        if 'access_token' in response:
            self.set_token(response['access_token'])
            self.user = response['user']

        return 'access_token' in response

    def set_token(self, token: str):
        self.session.headers['Authorization'] = f'Bearer {token}'

    def events(self):
        return self.session.get(
            self.endpoint_url + 'api/events'
        ).json()

    def make_key_agreement(self, user_id: int, user_key: bytes):
        self.session_keys[user_id] = dh.agreement(self.private_keys[user_id], user_key)
        print('Set session key:', self.set_session_key(user_id, self.session_keys[user_id]))

        return self.session_keys[user_id]

    def message_history(self, user_id: int):
        return self.session.get(
            self.endpoint_url + f'api/users/{user_id}/messages/history'
        ).json()

    def set_public_key(self, user_id: int):
        if user_id not in self.private_keys:
            self.private_keys[user_id] = dh.generate_key()

        return self.session.put(
            self.endpoint_url + f'api/users/{user_id}/key',
            json={
                'algo': 'DH+AES-256',
                'value': base64.b64encode(self.private_keys[user_id].public_key().export_key(format='DER')).decode()
            }
        ).json()

    def get_public_key(self, user_id: int):
        print(a := self.session.get(
            self.endpoint_url + f'api/users/{user_id}/keys'
        ).json())
        return a

    def get_my_public_key(self, user_id: int):
        return self.session.get(
            self.endpoint_url + f'api/users/{user_id}/myKeys'
        ).json()

    def get_session_key(self, user_id: int):
        return self.session.get(
            self.endpoint_url + f'api/users/{user_id}/sessionKey'
        ).json()

    def check_keys(self, user_id: int):
        if user_id not in self.session_keys:
            session_key = self.get_session_key(user_id)
            if session_key['key']:
                self.session_keys[user_id] = dh.aes256_cbc_decode(hashlib.sha256(self.password.encode()).digest(),
                                                                  base64.b64decode(session_key['key']['iv']),
                                                                  base64.b64decode(session_key['key']['value']))
            else:
                user_key = self.get_public_key(user_id)
                if not user_key['succeeded']:
                    return

                if user_id not in self.private_keys:
                    self.set_public_key(user_id)

                self.make_key_agreement(user_id, base64.b64decode(user_key['key']['value']))

        return self.session_keys[user_id]

    def send_message(self, user_id: int, content: str):
        session_key = self.check_keys(user_id)
        if not session_key:  # проверка существования ключа и запись сообщений для отправки после создания ключа
            self.messages_stack.append(self.Message(
                to_user_id=user_id,
                raw_content=content,
                encrypted_content=b'',
                iv=b''
            ))
            return

        while self.messages_stack:
            failed_message = self.messages_stack.pop(0)

            failed_message_data = dh.aes256_encode(session_key, failed_message.raw_content.encode())

            self.session.post(
                self.endpoint_url + f'api/users/{user_id}/messages/send',
                json={
                    'content': base64.b64encode(failed_message_data).decode()
                }
            )

        data = dh.aes256_encode(session_key, content.encode())

        response = self.session.post(
            self.endpoint_url + f'api/users/{user_id}/messages/send',
            json={
                'content': base64.b64encode(data).decode()
            }
        ).json()

        return response

    def set_session_key(self, user_id: int, session_key: bytes):
        iv = Random.new().read(16)
        encrypted_session_key = dh.aes256_cbc_encode(hashlib.sha256(self.password.encode()).digest(), iv, session_key)

        return self.session.put(
            self.endpoint_url + f'api/users/{user_id}/sessionKey',
            json={
                'algo': 'AES-256/CBC',
                'value': base64.b64encode(encrypted_session_key).decode(),
                'iv': base64.b64encode(iv).decode()
            }
        ).json()

    def events_handler(self):
        while True:
            events = self.events()
            print(events)
            for event in events['events']:
                if event['type'] == 'need_to_put_key':
                    self.set_public_key(event['data']['to_user_id'])
                elif event['type'] == 'new_key':
                    if event['data']['user_id'] not in self.private_keys:
                        self.set_public_key(event['data']['user_id'])

                    self.make_key_agreement(event['data']['user_id'],
                                            base64.b64decode(event['data']['value']))
                elif event['type'] == 'new_message' and event['data']['from_user_id'] != self.user['id']:
                    self.check_keys(event['data']['from_user_id'])

                    try:
                        message = dh.aes256_decode(self.session_keys[event["data"]["from_user_id"]],
                                                   base64.b64decode(event['data']['content']))
                    except ValueError:
                        print(f'failed to decode message from {event["data"]["from_user_id"]}')
                    else:
                        print(f'New message from {event["data"]["from_user_id"]}:', message.decode())
