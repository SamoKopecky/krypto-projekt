from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from crypto.util import padding
from crypto.cipher import AES
import base64
import socket

LOCALHOST = '127.0.0.1'
PEM_FORMAT = crypto.FILETYPE_PEM


# generujeme 2 pary RSA klucov
# 1. je z kniznice pyopenssl na pracovanie z certifikatnmy
# 2. je z kniznice cryptography z pracovanie z RSA
def generate_cryptography_rsa_keys():  # generacia RSA klucov z kniznice cryptography,
    keys = rsa.generate_private_key(
        public_exponent=65537,  # exponent public kluca
        key_size=2048,
        backend=default_backend()
    )
    public_key = keys.public_key()
    return keys, public_key


def generate_openssl_rsa_keys():  # generacia paru RSA klucov z opyopenssl
    keys = crypto.PKey()
    keys.generate_key(crypto.TYPE_RSA, 2048)
    pem_pkey = crypto.dump_publickey(PEM_FORMAT, keys)
    public_key = crypto.load_publickey(PEM_FORMAT, pem_pkey)
    return keys, public_key


def convert_key_from_ssl_to_cryptography(pkey=crypto.PKey()):  # konvertovanie z ssl to cyrptograhy
    # najprv dump_publickey prekonvertuje kluc na pem format a load_pem_public vycita z PEM formatu kluc
    public_key = serialization.load_pem_public_key(
        crypto.dump_publickey(PEM_FORMAT, pkey),
        default_backend(),
    )
    return public_key


def wait_for_acknowledgement(s):
    # program stoji pokial nedostane 'ack' spravu b pred 'ack' znamena ze je to bajt format
    while s.recv(
            2048) != b'ack':
        pass


def send_acknowledgement(s):
    s.send(b'ack')  # posielanie 'ack'


def finish_connection(s):  # koniec spojenia
    s.send(b'fin')
    wait_for_acknowledgement(s)
    print('ending communication')
    s.close()


def start_listening(port):
    if port is None:  # podmienka pridana len ked port uz zvoleny vpred
        port = int(input('choose port to listen to : '))  # uzivatel si zvoli port
    # AF_INET znamena ze komunikacia bude v IPV4, SOCK_STREAM je standarne nastavenie pre komunikaciu dvoch socketov
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # zaisti ze port mozem byt znova pouziti po ukonecni spojenia
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LOCALHOST, port))  # server nastavy na akom porte a adrese bude pocuvat
    server_socket.listen()  # tu zacne naozaj posluchat
    # prime komunikaciu ak sa niekto iny pripoji na port volby
    # conn je socket ktory ma cislo portu hosta, nahodne sa generuje
    conn, addr = server_socket.accept()
    print('connected to {}'.format(addr))
    return conn, addr


def start_sending():
    port = int(input('choose port to send to : '))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # zaisti ze port mozem byt znova pouziti po ukonecni spojenia
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket.connect((LOCALHOST, port))  # pripojenie na port a adresu volby
    return client_socket


def send_data(user_socket, data, string):
    print('sending {}'.format(string))
    user_socket.send(data)  # poslanie dat cez socket
    wait_for_acknowledgement(user_socket)  # cakanie na 'ack' spravu od hosta ktory prima zpravu


def receive_data(user_socket, string):
    data = user_socket.recv(2048)
    print('{} received'.format(string))
    send_acknowledgement(user_socket)  # poslanie'ack' spravy na ktoru caka odosielatel
    return data


def rsa_encrypt(data, public_key):
    cipher_text = public_key.encrypt(
        data,  # data ktore chceme zasifrovat
        padding.OAEP(  # padding je doplnenie nul na koniec spravy aby bola spravna dlzka spravhy
            padding.MGF1(hashes.SHA256()),  # OAEP je algoritmus a aj MGF1 je
            hashes.SHA256(),
            None
        )
    )
    return cipher_text


def rsa_decrypt(cipher_text, private_key):  # ten isty proces len je to desifrovanie
    data = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            padding.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )
    return data


def aes_encrypt(cipher, data):
    # vybranie encryptora z cipher objektu
    pad_data = padding.pad(data, AES.block_size)  # TODO:??
    return base64.b64encode(cipher.encrypt(pad_data))  # siforovanie dat
    # update nam ulozi data ktore budeme sifrovat
    # finalize znamena ze sa uz nedaju vlozit ziadne data a delej sifrovat


def aes_decrypt(cipher, c_data):  # to ise ale desiforvanie
    c_data = base64.b64decode(c_data)
    unpaded_c_data = padding.unpad(c_data)
    return cipher.decrypt(unpaded_c_data)
