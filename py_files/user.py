import utils
import os


class User:

    def __init__(self):
        """
            Creating variables to store things in later in the code, or initializing them right away
            other_* = variables of the other user we are communicating with
            active_socket = socket to communicate trough
        """
        self.aes_key = bytes()
        self.aes_iv = bytes()
        self.cipher = utils.Cipher
        self.my_certificate = utils.crypto.X509()
        self.private_key, self.public_key = utils.generate_cryptography_rsa_keys()
        self.other_certificate = utils.crypto.X509()
        self.other_public_key = utils.rsa.RSAPublicKey
        self.active_socket = utils.socket.socket()
        self.name = input('enter your name : ')
        self.received_messages = []

    def create_certificate_request(self):
        """
            We create certificate request in this function and convert keys from one lib to another
            request.get_subject is our info that the CA will put as issuer
            :return: returns created certificate request
        """
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

    def send_request_to_ca(self):
        """
            In here we get ready for communication, convert the certificate request to PEM format so
            that it can be sent and then we send it and then we close the connection with CA
        """
        client_socket = utils.start_sending()
        utils.send_data(client_socket, b'sending cert request', 'request to start communication')
        data_to_send = utils.crypto.dump_certificate_request(
            utils.PEM_FORMAT,
            self.create_certificate_request()
        )
        utils.send_data(client_socket, data_to_send, 'cert req')  # odoslanie ziadosti
        data = utils.receive_data(client_socket, 'cert')  # prijatie ziadost v PEM formate
        self.my_certificate = utils.crypto.load_certificate(utils.PEM_FORMAT, data)
        utils.finish_connection(client_socket)

    def exchange_certificates_and_keys(self):
        """
            We decide which user will be sending and listening and then exchange certificates and AES keys
        """
        state = input('listen or send : ')
        if state == 'listen':
            self.receiving_certificate()
            self.receiving_aes_key()
            self._create_aes_cipher()
        if state == 'send':
            self.sending_certificate()
            self.sending_aes_key()
            self._create_aes_cipher()

    def receiving_certificate(self):
        """
            first the user receives the certificate and then he sends his certificate
        """
        connection = utils.start_receiving(None)
        self.active_socket = connection
        data = utils.receive_data(self.active_socket, 'cert')
        self.other_certificate = utils.crypto.load_certificate(utils.PEM_FORMAT, data)
        data_to_send = utils.crypto.dump_certificate(utils.PEM_FORMAT, self.my_certificate)
        utils.send_data(self.active_socket, data_to_send, 'my cert')

    def receiving_aes_key(self):
        """
            same as function receiving_certificate but this time the user receives AES shared key
            aes is decrypted with RSA
        """
        key = utils.receive_data(self.active_socket, 'aes key')
        self.aes_iv = utils.receive_data(self.active_socket, 'aes iv')
        self.aes_key = utils.rsa_decrypt(key, self.private_key)

    def sending_certificate(self):
        """
            same thing as receive but reverse, user sends then listens for certificate
        """
        client_socket = utils.start_sending()
        self.active_socket = client_socket
        data_to_send = utils.crypto.dump_certificate(utils.PEM_FORMAT, self.my_certificate)
        utils.send_data(self.active_socket, data_to_send, 'my cert')
        data = utils.receive_data(self.active_socket, 'cert')
        self.other_certificate = utils.crypto.load_certificate(utils.PEM_FORMAT, data)

    def sending_aes_key(self):
        """
            this method generates the shared AES key and vector which it will then send to the other user
            encrypted with RSA
            key is 32 bytes long
            iv is 16 bytes long and can be sent in plain text
        """
        self.aes_key, self.aes_iv = os.urandom(32), os.urandom(16)
        self.other_public_key = utils.convert_key_from_ssl_to_cryptography(self.other_certificate.get_pubkey())
        data_to_send_1 = utils.rsa_encrypt(self.aes_key, self.other_public_key)
        utils.send_data(self.active_socket, data_to_send_1, 'aes key')
        utils.send_data(self.active_socket, self.aes_iv, 'aes iv')

    def _create_aes_cipher(self):
        """
            method for just creating aes cipher using CBC
        """
        if self.aes_key is None or self.aes_iv is None:
            raise ValueError('null value')
        self.cipher = utils.Cipher(utils.algorithms.AES(self.aes_key),
                                   utils.modes.CBC(self.aes_iv),
                                   utils.default_backend())

    def send_message(self):
        """
            method where you input some message a then encrypt it and send
        """
        message = input('input your message: ')
        c_message = utils.aes_encrypt(self.cipher, bytes(message, 'utf-8'))
        utils.send_data(self.active_socket, c_message, 'encrypted message')

    def receive_message(self):
        """
            this method is for receiving message and then decrypting it and then storing it
            in list of received message
        """
        c_message = utils.receive_data(self.active_socket, 'encrypted message')
        message = utils.aes_decrypt(self.cipher, c_message)
        print(message.decode())
        self.received_messages.append(message.decode())

    def start_conversation(self):
        """
            function for making conversation for now, at first you must choose listen on one user
            and then choose sent on second
        """
        conversation = True
        while conversation:
            state = input('choose if you expect to listen or '
                          'send message or quit(listen/send/quit): ')
            if state == 'listen':
                self.receive_message()
            if state == 'send':
                self.send_message()
            if state == 'quit':
                conversation = False


def use_user():
    """
        first function that is ran when user.py is ran
    """
    user = User()
    user.send_request_to_ca()
    user.exchange_certificates_and_keys()
    user.start_conversation()


use_user()
