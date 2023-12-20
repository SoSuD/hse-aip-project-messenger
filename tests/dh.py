from Crypto.Cipher import AES
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
from Crypto.Util.Padding import pad, unpad


def kdf(x):
    return x  # SHAKE256.new(x).read(32)


def generate_key(**kwargs):
    return ECC.generate(**kwargs, curve='p256')


def agreement(priv, pub):
    if isinstance(pub, bytes):
        pub = ECC.import_key(pub)

    return key_agreement(static_priv=priv, static_pub=pub, kdf=kdf)


def aes256_encode(key: bytes, data: bytes):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data, 32))


def aes256_decode(key: bytes, data: bytes):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(data), 32)


def aes256_cbc_encode(key: bytes, iv: bytes, data: bytes):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def aes256_cbc_decode(key: bytes, iv: bytes, data: bytes):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
