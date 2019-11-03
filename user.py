import os
import utils


class User:

    def __init__(self):
        self.aes_key = None
        self.aes_iv = None
        self.my_cert = utils.crypto.X509()
        self.private_key, self.public_key = utils.generate_cryptography_keys()
        self.other_cert = utils.crypto.X509()
        self.other_public_key = utils.rsa.RSAPublicKey
        self.active_socket = utils.socket.socket()
        self.name = input('enter your name : ')
        self.cipher = None
        self.received_messages = []

    def create_request(self):
        ssl_public_key = utils.crypto.PKey.from_cryptography_key(self.public_key)
        ssl_private_key = utils.crypto.PKey.from_cryptography_key(self.private_key)
        request = utils.crypto.X509Req()
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
        client_socket = utils.start_sending()
        utils.send_data(client_socket, b'sending cert request', 'request to start communication')
        data_to_send = utils.crypto.dump_certificate_request(utils.PEM_FORMAT, self.create_request())
        utils.send_data(client_socket, data_to_send, 'cert req')
        data = utils.receive_data(client_socket, 'cert')
        self.my_cert = utils.crypto.load_certificate(utils.PEM_FORMAT, data)
        utils.finish_conn(client_socket)

    def exchange_certs_and_keys(self):
        state = input('listen or send : ')
        if state == 'listen':
            self.listening()
        if state == 'send':
            self.sending()

    def listening(self):
        connection, address = utils.start_listening()
        self.active_socket = connection
        data = utils.receive_data(self.active_socket, 'cert')
        self.other_cert = utils.crypto.load_certificate(utils.PEM_FORMAT, data)
        data_to_send = utils.crypto.dump_certificate(utils.PEM_FORMAT, self.my_cert)
        utils.send_data(self.active_socket, data_to_send, 'my cert')
        key = utils.receive_data(self.active_socket, 'aes key')
        iv = utils.receive_data(self.active_socket, 'aes iv')
        self.aes_key = utils.rsa_decrypt(key, self.private_key)
        self.aes_iv = utils.rsa_decrypt(iv, self.private_key)

    def sending(self):
        # cert
        client_socket = utils.start_sending()
        self.active_socket = client_socket
        data_to_send = utils.crypto.dump_certificate(utils.PEM_FORMAT, self.my_cert)
        utils.send_data(self.active_socket, data_to_send, 'my cert')
        data = utils.receive_data(self.active_socket, 'cert')
        self.other_cert = utils.crypto.load_certificate(utils.PEM_FORMAT, data)
        # aes
        self.aes_key = os.urandom(32)
        self.aes_iv = os.urandom(16)
        self.other_public_key = utils.convert_key_from_ssl_to_crypt(self.other_cert.get_pubkey())
        data_to_send_1 = utils.rsa_encrypt(self.aes_key, self.other_public_key)
        data_to_send_2 = utils.rsa_encrypt(self.aes_iv, self.other_public_key)
        utils.send_data(self.active_socket, data_to_send_1, 'aes key')
        utils.send_data(self.active_socket, data_to_send_2, 'aes iv')
        self.cipher = utils.Cipher(utils.algorithms.AES(self.aes_key), utils.modes.CBC(self.aes_iv),
                                   utils.default_backend())

    def send_message(self):
        message = input('input your message: ')
        utils.aes_encrypt(self.cipher, message)
        utils.send_data(self.active_socket, message, 'encrypted message')

    def receive_message(self):
        message = utils.receive_data(self.active_socket, 'encrypted message').decode()
        print(message)
        self.received_messages.append(message)

    def start_conversation(self):

        state = input('listen or send : ')
        if state == 'listen':
            self.receive_message()
        if state == 'send':
            self.send_message()


def use_user():
    user = User()
    user.send_ca_request()
    user.exchange_certs_and_keys()
    print('aes : {}'.format(user.aes_key))
    print('iv : {}'.format(user.aes_iv))
    user.start_conversation()
