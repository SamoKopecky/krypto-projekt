from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os
import sys
import utils


class User:

    def __init__(self):
        """
            Creating variables to store things in later in the code, or initializing them right away
            other_* = variables of the other user we are communicating with
            active_socket = socket to communicate trough
        """
        self.aes_key = bytes()
        self.aes_iv = bytes()
        self.private_key, self.public_key = utils.generate_cryptography_rsa_keys()
        self.cipher = Cipher
        self.my_certificate = None
        self.other_certificate = None
        self.ca_certificate = None
        self.active_socket = utils.socket.socket()
        self.ca_port = int
        self.name = input('enter your name : ')
        self.received_messages = []

    def create_certificate_request(self):
        """
            We create certificate request in this function,
            email land common name are derived from the users chosen name,
            sign() functions fill the request with public key that's why we dont use the .public_key() method
            :return: returns created certificate request
        """
        name = utils.x509.Name([
            utils.x509.NameAttribute(utils.NameOID.COUNTRY_NAME, 'CZ'),
            utils.x509.NameAttribute(utils.NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME, 'Czech Republic'),
            utils.x509.NameAttribute(utils.NameOID.LOCALITY_NAME, 'Brno'),
            utils.x509.NameAttribute(utils.NameOID.ORGANIZATION_NAME, 'University of Technology'),
            utils.x509.NameAttribute(utils.NameOID.COMMON_NAME, '{}-vut.cz'.format(self.name)),
            utils.x509.NameAttribute(utils.NameOID.EMAIL_ADDRESS, '{}@vut.cz'.format(self.name)),
        ])
        return utils.x509.CertificateSigningRequestBuilder() \
            .subject_name(name) \
            .sign(self.private_key, utils.hashes.SHA256(), utils.default_backend())

    def send_request_to_ca(self):
        """
            In here we get ready for communication, convert the certificate request to PEM format so
            that it can be sent and then we send it and then we close the connection with CA
            if the verification failed try again
        """
        self.active_socket, self.ca_port = utils.start_sending(0, True)
        utils.send_data(self.active_socket, b'sending cert request', 'request to start communication')
        data_to_send = self.create_certificate_request().public_bytes(utils.PEM)
        utils.send_data(self.active_socket, data_to_send, 'cert req')
        received_data = utils.receive_data(self.active_socket, 'cert or verification failure')
        if received_data == b'verification failed':
            print('verification failed trying again')
            utils.finish_connection(self.active_socket)
            self.send_request_to_ca()
            return
        print('certificate was received successfully')
        self.my_certificate = utils.x509.load_pem_x509_certificate(received_data, utils.default_backend())
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
        self.active_socket = utils.start_receiving()
        self.receive_and_verify_certificate()
        self.send_certificate()

    def receive_and_verify_certificate(self):
        """
            certificate is received , if the verification is false an exception is thrown and program exists
        """
        received_data = utils.receive_data(self.active_socket, 'certificate')
        certificate = utils.x509.load_pem_x509_certificate(received_data, utils.default_backend())
        try:
            self.ca_certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                utils.padding.PKCS1v15(),
                certificate.signature_hash_algorithm
            )
        except utils.InvalidSignature:
            print('verification failed exiting program')
            sys.exit()

        self.other_certificate = certificate

    def get_ca_certificate(self):
        """
            requests the CA self singed certificate
        """
        ca_socket = utils.start_sending(self.ca_port)
        utils.send_data(ca_socket, b'requesting your public key', 'request for ca certificate')
        data = utils.receive_data(ca_socket, 'ca certificate')
        self.ca_certificate = utils.x509.load_pem_x509_certificate(data, utils.default_backend())
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
        self.active_socket = utils.start_sending()
        self.send_certificate()
        self.receive_and_verify_certificate()

    def send_certificate(self):
        """
            the certificate is sent
        """
        pem_certificate = self.my_certificate.public_bytes(utils.PEM)
        utils.send_data(self.active_socket, pem_certificate, 'certificate')

    def sending_aes_key(self):
        """
            this method generates the shared AES key and vector which it will then send to the other user
            encrypted with RSA
            key is 32 bytes long
            iv is 16 bytes long and can be sent in plain text
        """
        self.aes_key, self.aes_iv = os.urandom(32), os.urandom(16)
        other_public_key = self.other_certificate.public_key()
        data_to_send = utils.rsa_encrypt(self.aes_key, other_public_key)
        utils.send_data(self.active_socket, data_to_send, 'aes key')
        utils.send_data(self.active_socket, self.aes_iv, 'aes iv')

    def _create_aes_cipher(self):
        """
            method for just creating aes cipher using CBC mode and AES
        """
        if self.aes_key is None or self.aes_iv is None:
            raise ValueError('null value')
        self.cipher = Cipher(algorithms.AES(self.aes_key),
                             modes.CBC(self.aes_iv),
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
    user.get_ca_certificate()
    utils.write_to_file(user.my_certificate.public_bytes(utils.PEM),
                        utils.get_certs_dir('{}-cert.pem').format(user.name)
                        )
    user.exchange_certificates_and_keys()
    user.start_conversation()


use_user()