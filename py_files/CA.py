import utils


class CA:
    def __init__(self):
        """
            generating of RSA keys for CA
        """
        self.private_key, self.public_key = utils.generate_openssl_rsa_keys()
        self.list_of_certs = []

    def create_certificate_from_request(self, request):
        """
            before we create the certificate from the certificate request we fill the CA's info as a subject
            :param request: certificate request
            :return: returns created certificate
        """
        self.verify_certificate_request(request)
        cert = utils.crypto.X509()
        cert.set_serial_number(1000)
        cert.get_subject().countryName = 'CZ'
        cert.get_subject().stateOrProvinceName = 'Czech Republic'
        cert.get_subject().localityName = 'Brno'
        cert.get_subject().organizationName = 'University of Technology'
        cert.get_subject().organizationalUnitName = 'VUT'
        cert.get_subject().commonName = 'CA-vut.cz'
        cert.get_subject().emailAddress = 'CA@vut.cz'
        cert.set_issuer(request.get_subject())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24)  # 24 hours
        cert.set_pubkey(request.get_pubkey())
        cert.sign(self.private_key, 'sha256')
        self.list_of_certs.append(cert)
        return cert

    def verify_certificate_request(self, request):
        """
            TODO
        """
        pass

    def receive_certificate_request(self, port):
        """
            first we establish connection, in an infinite while loop we listen for message telling us what to do
            :param port: port to listen on
        """
        connection = utils.start_receiving(port)
        while True:
            data = connection.recv(2048)
            if data == b'sending cert request':
                self.send_certificate(connection)
            if data == b'fin':
                utils.send_acknowledgement(connection)
                print('ending connection, the same port can be used again')
                connection.close()
                break

    def send_certificate(self, connection):
        """
            first we convert the certificate request form PEM to x509Req format, create the certificate and
            send the certificate back to the user
            :param connection: port to send data with
        """
        print('ready to accept, sending ack')
        utils.send_acknowledgement(connection)
        data = utils.receive_data(connection, 'cert req')
        cert_req = utils.crypto.load_certificate_request(utils.PEM_FORMAT, data)
        cert = self.create_certificate_from_request(cert_req)
        data_to_send = utils.crypto.dump_certificate(utils.PEM_FORMAT, cert)
        utils.send_data(connection, data_to_send, 'cert')


def use_ca():
    """
        first function to run when CA.py is ran and before we start the infinite loop we
        get the the port to listen to for the rest of the runtime so we don't have to enter
        it every time
    """
    ca = CA()
    port = int(input('choose port to listen to : '))
    while True:
        ca.receive_certificate_request(port)


use_ca()
