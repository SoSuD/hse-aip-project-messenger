IS_PRODUCTION = False

clients = {
    'mobile.android': {
        'app_secret': b'0EjuhiSojazumexi1j155okuLAqo0Tu7498jixaqE1huliQaj0uj2i33Y8ep3a04',
        'jwt_secret': b'1234567890'
    }
}

access_token_lifetime = 3600



IS_DEBUG = not IS_PRODUCTION
