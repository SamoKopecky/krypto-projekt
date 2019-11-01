from methods import *
import os


class User:

    def __init__(self):
        self.aes_key = None
        self.aes_iv = None
        self.my_cert = crypto.X509()
        self.private_key, self.public_key = generate_cryptography_keys()
        self.other_cert = crypto.X509()
        self.other_public_key = rsa.RSAPublicKey
        self.active_socket = socket.socket()
        self.name = input('enter your name : ')

    def create_request(self):
        ssl_public_key = crypto.PKey.from_cryptography_key(self.public_key)
        ssl_private_key = crypto.PKey.from_cryptography_key(self.private_key)
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

    def exchange_certs_and_keys(self):
        state = input('listen or send : ')
        if state == 'listen':
            self.listening()
        if state == 'send':
            self.sending()

    def listening(self):
        connection, address = start_listening()
        self.active_socket = connection
        data = receive_data(self.active_socket, 'cert')
        self.other_cert = crypto.load_certificate(PEM_FORMAT, data)
        data_to_send = crypto.dump_certificate(PEM_FORMAT, self.my_cert)
        send_data(self.active_socket, data_to_send, 'my cert')
        key = receive_data(self.active_socket, 'aes key')
        iv = receive_data(self.active_socket, 'aes iv')
        self.aes_key = rsa_decrypt(key, self.private_key)
        self.aes_iv = rsa_decrypt(iv, self.private_key)

    def sending(self):
        # cert
        client_socket = start_sending()
        self.active_socket = client_socket
        data_to_send = crypto.dump_certificate(PEM_FORMAT, self.my_cert)
        send_data(self.active_socket, data_to_send, 'my cert')
        data = receive_data(self.active_socket,     'cert')
        self.other_cert = crypto.load_certificate(PEM_FORMAT, data)
        # aes
        self.aes_key = os.urandom(32)
        self.aes_iv = os.urandom(16)
        self.other_public_key = convert_key_from_ssl_to_crypt(user.other_cert.get_pubkey())
        data_to_send_1 = rsa_encrypt(self.aes_key, self.other_public_key)
        data_to_send_2 = rsa_encrypt(self.aes_iv, self.other_public_key)
        send_data(self.active_socket, data_to_send_1, 'aes key')
        send_data(self.active_socket, data_to_send_2, 'aes iv')


user = User()
user.send_ca_request()
user.exchange_certs_and_keys()
print('aes : {}'.format(user.aes_key))
print('iv : {}'.format(user.aes_iv))

