import utils
import os
import sys


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
        self.my_certificate_signature = bytes()
        self.private_key, self.public_key = utils.generate_cryptography_rsa_keys()
        self.ssl_public_key = utils.crypto.PKey.from_cryptography_key(self.public_key)
        self.ssl_private_key = utils.crypto.PKey.from_cryptography_key(self.private_key)
        self.other_certificate = utils.crypto.X509()
        self.other_certificate_signature = bytes()
        self.active_socket = utils.socket.socket()
        self.ca_port = int
        self.ca_public_key = utils.rsa.RSAPublicKey
        self.name = input('enter your name : ')
        self.received_messages = []

    def create_certificate_request(self):
        """
            We create certificate request in this function and convert keys from one lib to another
            request.get_subject is our info that the CA will put as issuer
            :return: returns created certificate request
        """
        request = utils.crypto.X509Req()
        request.get_subject().countryName = 'CZ'
        request.get_subject().stateOrProvinceName = 'Czech Republic'
        request.get_subject().localityName = 'Brno'
        request.get_subject().organizationName = 'University of Technology'
        request.get_subject().organizationalUnitName = 'VUT'
        request.get_subject().commonName = '{}-vut.cz'.format(self.name)
        request.get_subject().emailAddress = '{}@vut.cz'.format(self.name)
        request.set_pubkey(self.ssl_public_key)
        request.sign(self.ssl_private_key, 'sha256')
        return request

    def send_request_to_ca(self):
        """
            In here we get ready for communication, convert the certificate request to PEM format so
            that it can be sent and then we send it and then we close the connection with CA
            if the verification failed try again
        """
        self.active_socket, self.ca_port = utils.start_sending(None, True)
        utils.send_data(self.active_socket, b'sending cert request', 'request to start communication')
        data_to_send = utils.crypto.dump_certificate_request(
            utils.PEM_FORMAT,
            self.create_certificate_request()
        )
        utils.send_data(self.active_socket, data_to_send, 'cert req')
        first_data = utils.receive_data(self.active_socket, 'cert or verification failure')
        if first_data == b'verification failed':
            print('verification failed trying again')
            utils.finish_connection(self.active_socket)
            self.send_request_to_ca()
            return
        self.my_certificate_signature = utils.receive_data(self.active_socket, 'signature')
        self.my_certificate = utils.crypto.load_certificate(utils.PEM_FORMAT, first_data)
        utils.finish_connection(self.active_socket)

    def exchange_certificates_and_keys(self):
        """
            We decide which user will be sending and listening and then exchange certificates and AES keys
        """
        state = input('listen or send : ')
        if state == 'listen':
            self.finish_exchange_of_certificates()
            self.receiving_aes_key()
            self._create_aes_cipher()
        if state == 'send':
            self.start_exchange_of_certificates()
            self.sending_aes_key()
            self._create_aes_cipher()

    def finish_exchange_of_certificates(self):
        """
            first the user receives the certificate and then he sends his certificate
        """
        self.active_socket = utils.start_receiving(None)
        self.receive_and_verify_certificate()
        self.send_signature_and_certificate()

    def receive_and_verify_certificate(self):
        """
            certificate is received with the signature, if the verification is false an exception is thrown
            and program exists
        """
        self.get_ca_public_key()
        data_certificate = utils.receive_data(self.active_socket, 'certificate')
        data_signature = utils.receive_data(self.active_socket, 'signature')
        certificate = utils.crypto.load_certificate(utils.PEM_FORMAT, data_certificate)
        try:
            utils.rsa_verify(self.ca_public_key, data_signature, data_certificate)
        except Exception:
            print('verification failed exiting program')
            sys.exit()

        self.other_certificate = certificate
        self.other_certificate_signature = data_signature

    def get_ca_public_key(self):
        """
            requests the CA public key
        """
        ca_socket = utils.start_sending(self.ca_port, False)
        utils.send_data(ca_socket, b'requesting your public key', 'request for public key')
        data = utils.receive_data(ca_socket, 'ca public key')
        self.ca_public_key = utils.serialization.load_pem_public_key(
            data,
            utils.default_backend()
        )
        utils.finish_connection(ca_socket)

    def receiving_aes_key(self):
        """
            same as function receiving_certificate but this time the user receives AES shared key
            aes is decrypted with RSA
        """
        key = utils.receive_data(self.active_socket, 'aes key')
        self.aes_iv = utils.receive_data(self.active_socket, 'aes iv')
        self.aes_key = utils.rsa_decrypt(key, self.private_key)

    def start_exchange_of_certificates(self):
        """
            same thing as receive but reverse, user sends then listens for certificate
        """
        self.active_socket = utils.start_sending(None, False)
        self.send_signature_and_certificate()
        self.receive_and_verify_certificate()

    def send_signature_and_certificate(self):
        """
            the certificate and the signature is sent
        """
        pem_certificate = utils.crypto.dump_certificate(utils.PEM_FORMAT, self.my_certificate)
        utils.send_data(self.active_socket, pem_certificate, 'certificate')
        utils.send_data(self.active_socket, self.my_certificate_signature, 'signature')

    def sending_aes_key(self):
        """
            this method generates the shared AES key and vector which it will then send to the other user
            encrypted with RSA
            key is 32 bytes long
            iv is 16 bytes long and can be sent in plain text
        """
        self.aes_key, self.aes_iv = os.urandom(32), os.urandom(16)
        other_public_key = utils.from_ssl_to_cryptography(self.other_certificate.get_pubkey(), False)
        data_to_send = utils.rsa_encrypt(self.aes_key, other_public_key)
        utils.send_data(self.active_socket, data_to_send, 'aes key')
        utils.send_data(self.active_socket, self.aes_iv, 'aes iv')

    def _create_aes_cipher(self):
        """
            method for just creating aes cipher using CBC and AES
        """
        if self.aes_key is None or self.aes_iv is None:
            raise ValueError('null value')
        self.cipher = utils.Cipher(utils.algorithms.AES(self.aes_key),
                                   utils.modes.CBC(self.aes_iv),
                                   utils.default_backend()
                                   )

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
        first function that is ran when User.py is ran
    """
    user = User()
    user.send_request_to_ca()
    user.exchange_certificates_and_keys()
    user.start_conversation()


use_user()
