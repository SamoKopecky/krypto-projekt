import utils
import socket


class CA:
    def __init__(self):
        """
            generating of RSA keys for CA
        """
        self.private_key, self.public_key = utils.generate_openssl_rsa_keys()
        self.connection = socket.socket()
        self.dictionary_of_certs = {}

    def create_certificate_from_request(self, request):
        """
            before we create the certificate from the certificate request we fill the CA's info as a subject
            verify() throws crypto.Error if signatures aren't the same
            the certificate is signed here but we are not using the signature as our verification
            :param request: certificate request
            :return: returns created certificate
        """
        request.verify(request.get_pubkey())
        cert = utils.crypto.X509()
        cert.set_serial_number(420)
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
        return cert

    def receive_certificate_request(self, port):
        """
            first we establish connection, in an infinite while loop we listen for message telling us what to do
            if the verification of c_request fails communicate it to the host and try again
            :param port: port to listen on
        """
        self.connection = utils.start_receiving(port)
        while True:
            data = self.connection.recv(2048)
            if data == b'sending cert request':
                try:
                    self.send_certificate()
                except utils.crypto.Error:
                    print('Verification of the request failed ')
                    utils.send_data(self.connection, b'verification failed', 'verification failed')
                    continue
            if data == b'requesting your public key':
                self.send_public_key()
            if data == b'fin':
                utils.send_acknowledgement(self.connection)
                print('ending connection, the same port can be used again')
                self.connection.close()
                break

    def send_certificate(self):
        """
            first we convert the certificate request form PEM to x509Req format, create the certificate, sign it and
            send the certificate and the signature back to the user
        """
        print('ready to accept, sending ack')
        utils.send_acknowledgement(self.connection)
        data = utils.receive_data(self.connection, 'cert req')
        cert_req = utils.crypto.load_certificate_request(utils.PEM_FORMAT, data)
        cert = self.create_certificate_from_request(cert_req)
        pem_cert = utils.crypto.dump_certificate(utils.PEM_FORMAT, cert)
        signature = utils.rsa_sign(utils.from_ssl_to_cryptography(self.private_key), pem_cert)
        utils.send_data(self.connection, pem_cert, 'cert')
        utils.send_data(self.connection, signature, 'signature')
        self.dictionary_of_certs[cert] = signature

    def send_public_key(self):
        """
            send CA public key in PEM format
        """
        utils.send_acknowledgement(self.connection)
        pem_public_key = utils.crypto.dump_publickey(utils.PEM_FORMAT, self.public_key)
        utils.send_data(self.connection, pem_public_key, 'public key')


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
