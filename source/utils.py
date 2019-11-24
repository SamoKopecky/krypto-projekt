from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import platform
import os
import select
import socket
import sys

# constants
LOCALHOST = '127.0.0.1'
PEM = serialization.Encoding.PEM


def generate_rsa_keys():
    """
        generating RSA key pair from cryptography library, we use these for signing/verifying and
        encrypting/decrypting
        :return: private and public keys
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def wait_for_acknowledgement(active_socket):
    """
        wait for an acknowledgement from the other host/server if it doesn't come in 5 seconds
        or it doesn't match the acknowledgement message program exists
        :param active_socket: active socket of the host
    """
    ready = select.select([active_socket], [], [], 5)  # last parameter is timout in seconds
    data = bytes(0)
    if ready[0]:
        data = active_socket.recv(2048)
    if data == b'ack':
        return
    else:
        print('acknowledgement wasn\'t received exiting')
        sys.exit()


def send_acknowledgement(active_socket):
    """
        sending a byte message to indicate acknowledgement
        :param active_socket: active socket of the host
    """
    active_socket.send(b'ack')


def finish_connection(active_socket):
    """
        ending the communication
        :param active_socket: active socket of the host
    """
    active_socket.send(b'fin')
    wait_for_acknowledgement(active_socket)
    print('ending communication\n')
    active_socket.close()


def start_receiving(port=0):
    """
        function that start initializes connection of the receiver
        socket.AF_INET is the equivalent of IPV4
        socket.SOCK_STREAM is the standard setting for communication
        setsocckopt() is a function for ensuring that we can use that socket right after the connection ends
        then we bind to an address and a port and we start listening
        :param port: port number
        :return: randomly generated socket that the user was assigned
    """

    if port == 0:
        port = int(input('choose port to listen to : '))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LOCALHOST, port))
    server_socket.listen()
    connection, address = server_socket.accept()
    print('\nconnected to IP : {} PORT : {}'.format(address[0], address[1]))
    return connection


def start_sending(port=0, return_port=False):
    """
        function for initializing a connection of the sender same initialization of the
        socket as start_receiving functions
        :return: socket of the host we connected to
    """
    if port == 0:
        port = int(input('choose port to send to : '))
        print('\n')
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket.connect((LOCALHOST, port))
    if return_port:
        return client_socket, port
    return client_socket


def send_data(user_socket, data, string):
    """
        function to send a data and wait for confirmation
        :param user_socket: socket to send to
        :param data: data to send
        :param string: what the host is sending
    """
    print('sending : {}'.format(string))
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
    print('receiving : {}'.format(string))
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
        :param cipher_text: data to decrypt
        :param private_key: key to decrypt with
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


def rsa_verify_certificate(trusted_certificate, untrusted_certificate):
    trusted_certificate.public_key().verify(
        untrusted_certificate.signature,
        untrusted_certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        untrusted_certificate.signature_hash_algorithm
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
    padded_data = padder.update(data) + padder.finalize()
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
    return unpadder.update(data) + unpadder.finalize()


def write_to_file(data, file_path):
    """
        just a generic function that writes bytes to a file
        :param data: data to write in bytes
        :param file_path: path to the file to write to
    """
    with open(file_path, 'wb') as file:
        file.write(data)


def read_file(file_path):
    """
        reads the contents of a file
        :param file_path: file path to the file
        :return: read data
    """
    with open(file_path, 'r') as file:
        return file.read()


def get_certs_dir(file_name):
    """
        first we get the directory in which this file is located
        then we move 1 folder down and return the modified path
        :param file_name: name of the file
        :return: returns a string append by the file name
    """
    current_os = platform.system()
    if current_os == 'Windows':
        file_dir = os.getcwd()
        dirs = file_dir.split('\\')[:-1]
        return '\\'.join(dirs) + '\\certs\\{}'.format(file_name)
    elif current_os == 'Linux':
        file_dir = os.path.dirname(os.path.realpath(__file__))
        dirs = file_dir.split('/')[:-1]
        return '/'.join(dirs) + '/certs/{}'.format(file_name)
    else:
        print('unknown OS exiting')
        sys.exit()
