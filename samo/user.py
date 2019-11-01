from methods import *
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class User:

    def __init__(self):
        self.aes_key = None
        self.my_cert = crypto.X509()
        self.other_cert = crypto.X509()
        self.keys, self.public_key = generate_cryptography_keys()
        self.active_socket = socket.socket()
        self.name = input('enter your name : ')

    def create_request(self):
        ssl_public_key = crypto.PKey.from_cryptography_key(self.public_key)
        ssl_private_key = crypto.PKey.from_cryptography_key(self.keys)
        request = crypto.X509Req()
        request.get_subject().countryName = 'CZ'
        request.get_subject().stateOrProvinceName = 'Czech Republic'
        request.get_subject().localityName = 'Brno'
        request.get_subject().organizationName = 'University of Technology'
        request.get_subject().organizationalUnitName = 'VUT'
        request.get_subject().commonName = '{}-vut.cz'.format(self.name)
        request.get_subject().emailAddress = '{}@vut.cz'.format(self.name)
        request.set_pubkey(ssl_public_key)
        request.sign(ssl_private_key, 'sha256')
        return request

    def send_ca_request(self):
        client_socket = start_sending()
        send_data(client_socket, b'sending cert request', 'request to start communication')
        data_to_send = crypto.dump_certificate_request(PEM_FORMAT, self.create_request())
        send_data(client_socket, data_to_send, 'cert req')
        data = receive_data(client_socket, 'cert')
        self.my_cert = crypto.load_certificate(PEM_FORMAT, data)
        finish_conn(client_socket)

    def exchange_certs(self):
        state = input('listen or send : ')
        if state == 'listen':
            self.listening_for_cert()
        if state == 'send':
            self.sending_cert()

    def exchange_key(self):
        state = input('listen or send : ')
        if state == 'listen':
            self.listening_for_shared_key()
        if state == 'send':
            self.sending_shared_key()

    def listening_for_cert(self):
        connection, address = start_listening()
        self.active_socket = connection
        data = receive_data(connection, 'cert')
        self.other_cert = crypto.load_certificate(PEM_FORMAT, data)
        data_to_send = crypto.dump_certificate(PEM_FORMAT, self.my_cert)
        send_data(connection, data_to_send, 'my cert')

    def sending_cert(self):
        client_socket = start_sending()
        self.active_socket = client_socket
        data_to_send = crypto.dump_certificate(PEM_FORMAT, self.my_cert)
        send_data(client_socket, data_to_send, 'cert')
        data = receive_data(client_socket, 'cert')
        self.other_cert = crypto.load_certificate(PEM_FORMAT, data)

    def listening_for_shared_key(self):
        connection = self.active_socket
        data = connection.recv(2048)
        self.aes_key = data
        send_ack(connection)

    def sending_shared_key(self):
        client_socket = self.active_socket
        key = os.urandom(32)
        client_socket.send(key)
        wait_for_ack(client_socket)


user = User()
user.send_ca_request()
user.exchange_certs()
user.exchange_key()
print(user.other_cert.get_issuer().commonName)
