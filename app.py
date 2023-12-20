import dataclasses
import functools
import logging
import typing
import config
import crypto
import database

from flask import Flask, request, jsonify, abort
from request_models import *
from models import *

app = Flask(__name__)

pool = database.create_pool()

events_stack = []


@dataclasses.dataclass
class Event:
    type: str
    relation_user_ids: typing.List[int]
    # application_ids_notified: typing.List[str]
    data: typing.Dict
    time: int

    def dict(self):
        return {k: v for k, v in dataclasses.asdict(self).items()}


def validate_schema(schema: Schema): #Определение декораторов для валидации JSON и аргументов запросов.
    """
        Декоратор для валидации входящего JSON запроса согласно заданной схеме.

        :param schema (Schema): Схема, которая используется для валидации данных.

        Применяет переданную схему для валидации JSON содержимого запроса. Если данные не валидны,
        возвращает ответ с ошибкой 400 и сообщением о валидационных ошибках.

        :return: function: обернутая функция, которая вводит валидацию запросов для декорируемой функции.
    """
    def inner_decorator(func):
        @functools.wraps(func)
        def magic(*args, **kwargs):
            try:
                model = schema.load(request.json)
            except ValidationError as err:
                return jsonify(err.messages), 400

            return func(model, *args, **kwargs)

        return magic

    return inner_decorator


def validate_args(schema: Schema):
    """
           Декоратор для валидации аргументов запроса.

           Валидирует query параметры запроса (request.args) и передаёт обработанные данные в декорируемую функцию.

           Возвращает ошибку 400 с описанием ошибки валидации, если данные не соответствуют схеме.

           :return: function:обернутая функция, которая добавляет валидацию к декорируемой функции.
       """
    def inner_decorator(func):
        @functools.wraps(func)
        def magic(*args, **kwargs):
            try:
                model = schema.load(request.args)
            except ValidationError as err:
                return jsonify(err.messages), 400

            return func(model, *args, **kwargs)

        return magic

    return inner_decorator


def validate_signature(func):#Декоратор для проверки подписи запроса.
    """
           Декоратор для проверки JWT токена пользователя в заголовках запроса.

           Проверяет наличие 'X-Client-ID' и токена авторизации в заголовках запроса, а также валидность самого токена.

           В случае неуспеха обработки токена или если токен отсутствует, функция вернёт ошибку HTTP 400 или HTTP 401.

           :param func: Функция, к которой применяется декоратор.

           :return: Обёрнутая функция с проверкой токена.
       """
    @functools.wraps(func)
    def magic(*args, **kwargs):
        client_id = request.headers.get('X-Client-ID')
        if not client_id:
            abort(400)

        if client_id not in config.clients:
            abort(400)

        if config.IS_PRODUCTION:
            signature = request.headers.get('Signature')
            if not signature:
                abort(400)

            if signature != crypto.request_signature(config.clients[client_id]['app_secret'], request.data):
                abort(400)

        return func(*args, **kwargs)

    return magic


def validate_token(func): #проверка токена
    @functools.wraps(func)
    def magic(*args, **kwargs):
        client_id = request.headers.get('X-Client-ID')
        if not client_id:
            abort(400)

        if client_id not in config.clients:
            abort(400)

        token = request.headers.get('Authorization')
        if not token:
            abort(401)

        token = token.replace('Bearer ', '')

        try:
            payload = crypto.decode_user_token(token, config.clients[client_id]['jwt_secret'])
        except ValueError:
            logging.exception('Error')
            return abort(401)

        return func(payload, *args, **kwargs)

    return magic


@app.errorhandler(400)
def bad_request_handler(_):
    return jsonify(succeeded=False), 400


@app.route('/api/users/create', methods=['POST'])
@validate_signature
@validate_schema(UserCredentials())
def users_signup(data):
    with pool.acquire() as conn, conn.cursor() as cur:
        if User(username=data['username']).get_one(cur):
            return jsonify(succeeded=False,
                           errors=[{'username': ['Username already exists']}]), 400

        user = User(username=data['username'],
                    password_hash=crypto.hash_password(data['password']),
                    creation_time=round(time.time()))
        user.add(cur)

    client_id = request.headers.get('X-Client-ID')
    client = config.clients[client_id]

    return jsonify(succeeded=True,
                   user=user.serialize(include_secret_fields=False),
                   access_token=crypto.new_user_token(
                       user,
                       client['jwt_secret'],
                       client_id,
                       application_id=str(data['application_id'])
                   )), 201


@app.route('/api/users/auth', methods=['POST'])
@validate_signature
@validate_schema(UserCredentials())
def users_auth(data):
    with pool.acquire() as conn, conn.cursor() as cur:
        user = User(username=data['username'],
                    password_hash=crypto.hash_password(data['password']))
        if not user.get_one(cur):
            return jsonify(succeeded=False,
                           errors=[{'': ['Invalid credentials']}]), 403

    client_id = request.headers.get('X-Client-ID')
    client = config.clients[client_id]

    return jsonify(succeeded=True,
                   user=user.serialize(include_secret_fields=False),
                   access_token=crypto.new_user_token(
                       user,
                       client['jwt_secret'],
                       client_id,
                       application_id=str(data['application_id'])
                   )), 201


@app.route('/api/users/my', methods=['GET'])
@validate_token
def users_my(payload):
    with pool.acquire() as conn, conn.cursor() as cur:
        user = User(id=payload['sub'])
        if not user.get_one(cur):
            abort(500)

    return jsonify(succeeded=True,
                   user=user.serialize(include_secret_fields=False))


@app.route('/api/users/<int:user_id>/key', methods=['PUT'])
@validate_token
# @validate_signature
@validate_schema(DHKeyRequest())
def users_asymmetric_key_set(data, payload, user_id: int):
    with pool.acquire() as conn, conn.cursor() as cur:
        public_key = ChatPublicKey(user_id=payload['sub'],
                                   to_user_id=user_id,
                                   value=data['value'],
                                   creation_time=round(time.time()))
        public_key.add(cur)

        events_stack.append(Event(
            type='new_key',
            relation_user_ids=[user_id],
            data=public_key.serialize(),
            time=public_key.creation_time
        ))

    return jsonify(succeeded=True)


@app.route('/api/users/<int:user_id>/keys', methods=['GET'])
@validate_token
def public_key_get(payload, user_id: int):
    with pool.acquire() as conn, conn.cursor() as cur:
        public_key = ChatPublicKey(user_id=user_id,
                                   to_user_id=payload['sub'])
        if not public_key.get_one(cur, order='ORDER BY `id` DESC'):
            events_stack.append(Event(
                type='need_to_put_key',
                relation_user_ids=[user_id],
                data={
                    'to_user_id': payload['sub']
                },
                time=round(time.time())
            ))

            return jsonify(succeeded=False,
                           errors=[{'': 'User has not installed a public key'}]), 400

    return jsonify(succeeded=True,
                   key=public_key.serialize())


@app.route('/api/users/<int:user_id>/myKeys', methods=['GET'])
@validate_token
def my_public_key_get(payload, user_id: int):
    with pool.acquire() as conn, conn.cursor() as cur:
        public_key = ChatPublicKey(user_id=payload['sub'],
                                   to_user_id=user_id)
        if not public_key.get_one(cur, order='ORDER BY `id` DESC'):
            return jsonify(succeeded=True,
                           key=None)

    return jsonify(succeeded=True,
                   key=public_key.serialize())


@app.route('/api/users/<int:user_id>/sessionKey', methods=['PUT']) #сохранение в бд session key
@validate_token
# @validate_signature
@validate_schema(SessionKeyRequest())
def users_session_key_set(data, payload, user_id: int):
    with pool.acquire() as conn, conn.cursor() as cur:
        session_key = SessionKey(from_user_id=payload['sub'],
                                 to_user_id=user_id,
                                 value=data['value'],
                                 iv=data['iv'],
                                 creation_time=round(time.time()))
        session_key.add(cur)

    return jsonify(succeeded=True)


@app.route('/api/users/<int:user_id>/sessionKey', methods=['GET']) #получение session key
@validate_token
def users_session_key_get(payload, user_id: int):
    with pool.acquire() as conn, conn.cursor() as cur:
        session_key = SessionKey(from_user_id=payload['sub'],
                                 to_user_id=user_id)
        if not session_key.get_one(cur, order='ORDER BY `id` DESC'):
            return jsonify(succeeded=True,
                           key=None)

    return jsonify(succeeded=True,
                   key=session_key.serialize())


@app.route('/api/users/<int:user_id>/messages/send', methods=['POST'])
@validate_token
@validate_schema(MessageRequest())
def users_messages_send(data, payload, user_id: int):
    with pool.acquire() as conn, conn.cursor() as cur:
        message = Message(from_user_id=payload['sub'],
                          to_user_id=user_id,
                          content=data['content'],
                          time=round(time.time()))
        message.add(cur)

    print('added to events stack')

    events_stack.append(Event(
        type='new_message',
        relation_user_ids=[message.from_user_id, message.to_user_id],
        data=message.serialize(),
        time=message.time
    ))

    return jsonify(succeeded=True,
                   message=message.serialize())


@app.route('/api/users/<int:user_id>/messages/history', methods=['GET'])
@validate_token
@validate_args(SortRequest())
def users_messages_history(data, payload, user_id: int):
    with pool.acquire() as conn, conn.cursor() as cur:
        cur.execute("SELECT * from `messages` "
                    "WHERE (`from_user_id` = %s AND `to_user_id` = %s) "
                    "OR (`from_user_id` = %s AND `to_user_id` = %s) "
                    f"ORDER BY `time` {data['order']} LIMIT {data['items'] * data['page']}, {data['items']};",
                    (payload['sub'], user_id, user_id, payload['sub']))
        messages = cur.fetchall()

    return jsonify(succeeded=True,
                   messages=messages)


@app.route('/api/chats/get', methods=['GET'])
@validate_token
@validate_args(SortRequest())
def chats_get(data, payload):
    with pool.acquire() as conn, conn.cursor() as cur:
        cur.execute("SELECT `users`.* from `public_keys` "
                    "INNER JOIN `users` ON `users`.`id` = `public_keys`.`user_id` "
                    "OR `users`.`id` = `public_keys`.`to_user_id` "
                    "WHERE `public_keys`.`user_id` = %s OR `public_keys`.`to_user_id` = %s "
                    f"GROUP BY `users`.`id` "
                    f"ORDER BY `id` {data['order']} LIMIT {data['items'] * data['page']}, {data['items']};",
                    (payload['sub'], payload['sub']))
        users = [User(**kwargs).serialize(include_secret_fields=False) for kwargs in cur.fetchall()]

    return jsonify(succeeded=True,
                   users=users)


@app.route('/api/events', methods=['GET'])
@validate_token
def events(payload):
    start_time = time.time()
    while time.time() - start_time < 25: #ожидание событий
        relation_events = []
        for event in events_stack:
            if not event.relation_user_ids:
                events_stack.remove(event)
                continue

            if payload['sub'] in event.relation_user_ids:
                dict_event = event.dict()
                dict_event.pop('relation_user_ids')
                event.relation_user_ids.remove(payload['sub'])

                relation_events.append(dict_event)

        if relation_events:
            return jsonify(succeeded=True,
                           events=relation_events)

        time.sleep(0.1)

    return jsonify(succeeded=True,
                   events=[])
