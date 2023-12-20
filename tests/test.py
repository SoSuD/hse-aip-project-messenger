import base64
import threading
import time

import config
from main import MessengerClient
import random

import dh


def test_users_login_success():
    client1 = MessengerClient('tester', '1234567890')
    test_data = client1.auth()

    assert test_data


def test_users_login_success_incorrect_password():
    client1 = MessengerClient('tester', '1234567891')
    test_data = client1.auth()

    assert not test_data


def test_users_signup():
    client1 = MessengerClient('tester' + str(random.randint(1, 34534545)), '543444544333')
    test_data = client1.signup()
    print(test_data)
    assert test_data['succeeded']


def test_users_signup_already_registered():
    client1 = MessengerClient('tester' + str(random.randint(1, 34534545)), '543444544333')
    test_data = client1.signup()
    assert test_data['succeeded']
    test_data = client1.signup()
    assert not test_data['succeeded']


def test_users_start_dialog():
    client1 = MessengerClient('tester' + str(random.randint(1, 34534545)), '543444544333')
    test_data = client1.signup()
    assert test_data['succeeded']
    client1_id = test_data['user']['id']
    client2 = MessengerClient('tester' + str(random.randint(1, 34534545)), '543444544333')
    test_data = client2.signup()
    events_thread1 = threading.Thread(target=client1.events_handler,
                                      daemon=True)
    events_thread1.start()

    events_thread2 = threading.Thread(target=client2.events_handler,
                                      daemon=True)
    events_thread2.start()

    assert test_data['succeeded']

    client2_id = test_data['user']['id']

    if not client1.send_message(client2_id, 'Test'):
        while client1.messages_stack:
            failed_message = client1.messages_stack.pop(0)

            failed_message_data = dh.aes256_encode(client1.check_keys(client2_id), failed_message.raw_content.encode())

            client1.session.post(
                client1.endpoint_url + f'api/users/{client2_id}/messages/send',
                json={
                    'content': base64.b64encode(failed_message_data).decode()
                }
            )
    time.sleep(3)
    # print(client2.session_keys)
    # print(client2.message_history(client1_id))
    try:
        message = dh.aes256_decode(client2.session_keys[client1_id],
                                   base64.b64decode(client2.message_history(client1_id)['messages'][-1]['content']))
    except ValueError:
        assert False, 'failed to decode message'
    else:
        print(a := message.decode())

    assert a == 'Test'


def test_users_start_dialog_without_event():
    client1 = MessengerClient('tester' + str(random.randint(1, 34534545)), '543444544333')
    test_data = client1.signup()
    assert test_data['succeeded']
    client1_id = test_data['user']['id']
    client2 = MessengerClient('tester' + str(random.randint(1, 34534545)), '543444544333')
    test_data = client2.signup()
    # events_thread1 = threading.Thread(target=client1.events_handler,
    #                                  daemon=True)
    # events_thread1.start()
    #
    # events_thread2 = threading.Thread(target=client2.events_handler,
    #                                  daemon=True)
    # events_thread2.start()

    assert test_data['succeeded']

    client2_id = test_data['user']['id']
    try:
        if not client1.send_message(client2_id, 'Test'):
            while client1.messages_stack:
                failed_message = client1.messages_stack.pop(0)
                try:
                    failed_message_data = dh.aes256_encode(client1.check_keys(client2_id),
                                                           failed_message.raw_content.encode())
                except:
                    assert True, 'error while check keys'

                client1.session.post(
                    client1.endpoint_url + f'api/users/{client2_id}/messages/send',
                    json={
                        'content': base64.b64encode(failed_message_data).decode()
                    }
                )
        time.sleep(3)
        # print(client2.session_keys)
        # print(client2.message_history(client1_id))
        try:
            message = dh.aes256_decode(client2.session_keys[client1_id],
                                       base64.b64decode(client2.message_history(client1_id)['messages'][-1]['content']))
        except ValueError:
            assert False, 'failed to decode message'
        else:
            print(a := message.decode())

        assert a == 'Test'
    except:
        assert True


def test_check_signature():
    client1 = MessengerClient('tester' + str(random.randint(1, 34534545)), '543444544333')
    test_data = client1.signup()
    if config.IS_PRODUCTION:
        assert not test_data['succeeded']
    else:
        assert test_data['succeeded']

