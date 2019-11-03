from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import socket

LOCALHOST = '127.0.0.1'
PEM_FORMAT = crypto.FILETYPE_PEM


def generate_cryptography_keys():
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = keys.public_key()
    return keys, public_key


def generate_openssl_keys():
    keys = crypto.PKey()
    keys.generate_key(crypto.TYPE_RSA, 2048)
    pem_pkey = crypto.dump_publickey(PEM_FORMAT, keys)
    public_key = crypto.load_publickey(PEM_FORMAT, pem_pkey)
    return keys, public_key


def convert_key_from_ssl_to_crypt(pkey=crypto.PKey()):
    public_key = serialization.load_pem_public_key(
        crypto.dump_publickey(PEM_FORMAT, pkey),
        default_backend(),
    )
    return public_key


def wait_for_ack(s):
    while s.recv(2048) != b'ack':
        pass


def send_ack(s):
    s.send(b'ack')


def finish_conn(s):
    s.send(b'fin')
    wait_for_ack(s)
    print('ending communication')
    s.close()


def start_listening():
    port = int(input('choose port to listen to : '))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((LOCALHOST, port))
    server_socket.listen()
    conn, addr = server_socket.accept()
    print('connected to {}'.format(addr))
    return conn, addr


def start_sending():
    port = int(input('choose port to send to : '))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((LOCALHOST, port))
    return client_socket


def send_data(user_socket, data, string):
    print('sending {}'.format(string))
    user_socket.send(data)
    wait_for_ack(user_socket)


def receive_data(user_socket, string):
    data = user_socket.recv(2048)
    print('{} received'.format(string))
    send_ack(user_socket)
    return data


def rsa_encrypt(data, public_key):
    cypher = public_key.encrypt(
        data,
        padding.OAEP(
            padding.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )
    return cypher


def rsa_decrypt(cypher, private_key):
    data = private_key.decrypt(
        cypher,
        padding.OAEP(
            padding.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )
    return data


def aes_encrypt(cipher, data):
    encryptor = cipher.encryptor()
    return encryptor.update(bytes(data, 'utf-8')) + encryptor.finalize()


def aes_decrypt(cipher, c_data):
    decryptor = cipher.decryptor()
    return decryptor.update(cipher) + decryptor.finalize()
