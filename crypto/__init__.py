import hashlib
import hmac
import time
import jwt

import config

from models import User


def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()


def request_signature(client_secret: bytes, data: bytes):
    return hmac.new(client_secret, data, hashlib.sha256).hexdigest()


def new_user_token(user: User, client_secret: str, client_id: str, **kwargs):
    now = round(time.time())
    kwargs.update({
        'sub': user.id,
        'client_id': client_id,
        'iat': now - 1,
        'nbf': now - 1,
        'exp': now + config.access_token_lifetime,
        'iss': client_id
    })
    return jwt. \
        encode(
            kwargs,
            client_secret,
            algorithm='HS256',
        )


def decode_user_token(token: str, client_secret: str):
    try:
        return jwt.decode(token, client_secret, algorithms='HS256')
    except jwt.InvalidTokenError as e:
        raise ValueError from e
