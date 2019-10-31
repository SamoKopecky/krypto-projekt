from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
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


def generate_ssl_keys():
    keys = crypto.PKey()
    keys.generate_key(crypto.TYPE_RSA, 2048)
    pem_pkey = crypto.dump_publickey(PEM_FORMAT, keys)
    public_key = crypto.load_publickey(PEM_FORMAT, pem_pkey)
    return keys, public_key


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
