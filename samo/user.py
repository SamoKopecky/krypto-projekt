from methods import *


class User:

    def __init__(self):
        self.my_cert = crypto.X509()
        self.other_cert = crypto.X509()
        self.keys, self.public_key = generate_cryptography_keys()
        self.name = input('enter your name : ')

    def create_request(self):
        ssl_public_key = crypto.PKey.from_cryptography_key(self.public_key)
        ssl_private_key = crypto.PKey.from_cryptography_key(self.keys)
        request = crypto.X509Req()
        request.get_subject().countryName = 'EN'
        request.get_subject().stateOrProvinceName = 'Czech Republic'
        request.get_subject().localityName = 'Brno'
        request.get_subject().organizationName = 'University of Technology'
        request.get_subject().organizationalUnitName = 'FEKT'
        request.get_subject().commonName = '{}-fekt.cz'.format(self.name)
        request.get_subject().emailAddress = '{}@fekt.cz'.format(self.name)
        request.set_pubkey(ssl_public_key)
        request.sign(ssl_private_key, 'sha256')
        return request

    def send_ca_request(self):
        client_socket = start_sending()
        print('sending request to start communication')
        client_socket.send(b'sending cert request')
        wait_for_ack(client_socket)
        data_to_send = crypto.dump_certificate_request(PEM_FORMAT, self.create_request())
        client_socket.send(data_to_send)
        print('cert request sent')
        wait_for_ack(client_socket)
        data = client_socket.recv(2048)
        print('cert received')
        send_ack(client_socket)
        self.my_cert = crypto.load_certificate(PEM_FORMAT, data)
        finish_conn(client_socket)

    def exchange_keys(self):
        state = input('listen or send : ')
        if state == 'listen':
            self.listening()
        if state == 'send':
            self.sending()

    def listening(self):
        connection, address = start_listening()
        data = connection.recv(2048)
        send_ack(connection)
        print('cert received, sending ack')
        self.other_cert = crypto.load_certificate(PEM_FORMAT, data)
        print('sending my cert to other user')
        data_to_send = crypto.dump_certificate(PEM_FORMAT, self.my_cert)
        connection.send(data_to_send)
        wait_for_ack(connection)

    def sending(self):
        client_socket = start_sending()
        data_to_send = crypto.dump_certificate(PEM_FORMAT, self.my_cert)
        client_socket.send(data_to_send)
        print('cert sent, waiting for ack, and his cert')
        wait_for_ack(client_socket)
        data = client_socket.recv(2048)
        send_ack(client_socket)
        print('cert received, sending ack')
        self.other_cert = crypto.load_certificate(PEM_FORMAT, data)


user = User()
user.send_ca_request()
user.exchange_keys()
print(user.other_cert.get_issuer().commonName)
