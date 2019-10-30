from OpenSSL import crypto
import socket

LOCALHOST = '127.0.0.1'


def create_keys():
    keys = crypto.PKey()
    keys.generate_key(crypto.TYPE_RSA, 2048)  # generovanie public aj private keys
    pem_pkey = crypto.dump_publickey(crypto.FILETYPE_PEM, keys)
    public_key = crypto.load_publickey(crypto.FILETYPE_PEM, pem_pkey)
    return keys, public_key


def send_data(host, port, msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(msg)


def receive_data(host, port):
    host = '127.0.0.1'
    port = 12345
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen()
    conn, addr = s.accept()
    print('connect {}'.format(addr))
    while True:
        data = conn.recv(4096)
        if not data:
            break
    s.close()
    return data

def wait_for_ack(s):
    while s.recv(2048) != b'ack':
        print('waiting for ack')
    print('msg acked')
