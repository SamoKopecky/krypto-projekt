from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from OpenSSL import crypto
import socket

"""
    constants
"""
LOCALHOST = '127.0.0.1'
PEM_FORMAT = crypto.FILETYPE_PEM


def generate_cryptography_rsa_keys():
    """
        generating RSA key pair from cryptography library, we use these for signing/verifying and
        encrypting/decrypting
        :return: private and public keys
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # exponent public kluca
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def generate_openssl_rsa_keys():
    """
        generating RSA key pair from pyopenssl library, we use these for certificates
        :return: private and public keys
    """
    private_key = crypto.PKey()
    private_key.generate_key(crypto.TYPE_RSA, 2048)
    pem_pkey = crypto.dump_publickey(PEM_FORMAT, private_key)
    public_key = crypto.load_publickey(PEM_FORMAT, pem_pkey)
    return private_key, public_key


def convert_key_from_ssl_to_cryptography(pkey: crypto.PKey):
    """
        convert pyopenssl RSA key to PEM format then we import it to cryptography RSA public key
        from PEM format
        :param pkey: public key
        :return: RSA key from cryptography library
    """
    return serialization.load_pem_public_key(
        crypto.dump_publickey(PEM_FORMAT, pkey),
        default_backend(),
    )


def wait_for_acknowledgement(active_socket):
    """
        wait for a n acknowledgement from the other host/server
        :param active_socket: active socket of the host
    """
    while active_socket.recv(2048) != b'ack':
        pass


def send_acknowledgement(active_socket):
    """
        sending a byte message to indicate acknowledgement
        :param active_socket: active socket of the host
    """
    active_socket.send(b'ack')  # posielanie 'ack'


def finish_connection(active_socket):
    """
        ending the communication
        :param active_socket: active socket of the host
    """
    active_socket.send(b'fin')
    wait_for_acknowledgement(active_socket)
    print('ending communication')
    active_socket.close()


def start_receiving(port):
    """
        function that start initializes connection of the receiver
        socket.AF_INET is the equivalent of IPV4
        socket.SOCK_STREAM is the standard setting for communication
        setsocckopt() is a function for ensuring that we can use that socket right after the connection ends
        then we bind to an address and a port and we start listening
        :param port: port number
        :return: randomly generated socket that the user was assigned
    """
    if port is None:
        port = int(input('choose port to listen to : '))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LOCALHOST, port))
    connection, address = server_socket.accept()
    print('connected to {}'.format(address))
    return connection


def start_sending():
    """
        function for initializing a connection of the sender
        same initialization of the socket as start_receiving
        :return: socket of the host we connected to
    """
    port = int(input('choose port to send to : '))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket.connect((LOCALHOST, port))
    return client_socket


def send_data(user_socket, data, string):
    """
        function to send a data and wait for confirmation
        :param user_socket: socket to send to
        :param data: data to send
        :param string: what the host is sending
    """
    print('sending {}'.format(string))
    user_socket.send(data)
    wait_for_acknowledgement(user_socket)


def receive_data(user_socket, string):
    """
        function for receving data
        :param user_socket: socket to receive from
        :param string: what is the host receiving
        :return: returns the received data
    """
    data = user_socket.recv(2048)
    print('{} received'.format(string))
    send_acknowledgement(user_socket)
    return data


def rsa_encrypt(data, public_key):
    """
        function for encrypting data with RSA
        OAEP padding used
        SHA256 used
        :param data: data to encrypt
        :param public_key: key to encrypt with
        :return: encrypted data
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            padding.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )


def rsa_decrypt(cipher_text, private_key):
    """
        function for decrypting with RSA
        same algorithms used for padding and hashes as encryption
        :param cipher_text:
        :param private_key:
        :return: decrypted data
    """
    return private_key.decrypt(
        cipher_text,
        padding.OAEP(
            padding.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )


def aes_encrypt(cipher, data: bytes):
    """
        function to encrypt data with PKCS7 padding algorithm
        finalize() function ensures the data is final and can't be changed again
        :param cipher: cipher object created in user class
        :param data: data to encrypt
        :return: the encrypted data
    """
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(cipher.algorithm.block_size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()


def aes_decrypt(cipher, c_data: bytes):
    """
        function to decrypt data with PKCS7 padding algorithm
        finalize() function ensures the data is final and can't be changed again
        :param cipher: cipher object created in user class
        :param c_data: encrypted data
        :return: the decrypted data
    """
    decryptor = cipher.decryptor()
    data = decryptor.update(c_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(cipher.algorithm.block_size).unpadder()
    unpaded_data = unpadder.update(data)
    unpaded_data += unpadder.finalize()
    return unpaded_data
