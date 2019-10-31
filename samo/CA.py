from methods import *


class CA:
    def __init__(self):
        self.keys, self.public_key = generate_ssl_keys()
        self.list_of_certs = []
        self.listen_for_cert_req()

    def create_cert(self, request):
        # https://en.wikipedia.org/wiki/Public_key_certificate#Common_fields

        if request.verify(request.get_pubkey()):
            cert = crypto.X509()
            cert.set_serial_number(1000)
            cert.get_subject().countryName = 'CZ'
            cert.get_subject().stateOrProvinceName = 'Czech Republic'
            cert.get_subject().localityName = 'Brno'
            cert.get_subject().organizationName = 'University of Technology'
            cert.get_subject().organizationalUnitName = 'FEKT'
            cert.get_subject().commonName = 'CA-fekt.cz'
            cert.get_subject().emailAddress = 'CA@fekt.cz'
            cert.set_issuer(request.get_subject())
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(60 * 60 * 24)
            cert.set_pubkey(request.get_pubkey())
            cert.sign(self.keys, 'sha256')
            self.list_of_certs.append(cert)
            return cert

    def listen_for_cert_req(self):
        connection, address = start_listening()
        while True:
            data = connection.recv(2048)
            if data == b'sending cert request':
                print('ready to accept, sending ack')
                send_ack(connection)
                data = connection.recv(2048)
                print('cert req received')
                send_ack(connection)
                cert_req = crypto.load_certificate_request(PEM_FORMAT, data)
                cert = self.create_cert(cert_req)
                data_to_send = crypto.dump_certificate(PEM_FORMAT, cert)
                connection.send(data_to_send)
                print('cert sent')
                wait_for_ack(connection)
            if data == b'fin':
                send_ack(connection)
                print('ending connection')
                connection.close()
                break


ca = CA()
while True:
    ca.listen_for_cert_req()
