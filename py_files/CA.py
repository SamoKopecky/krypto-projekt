import datetime
import socket
import utils


def fill_certificate_name():
    """
        static method for filling the name object
        :return: name object filled with CA info
    """
    return utils.x509.Name([
        utils.x509.NameAttribute(utils.NameOID.COUNTRY_NAME, 'CZ'),
        utils.x509.NameAttribute(utils.NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME, 'Czech Republic'),
        utils.x509.NameAttribute(utils.NameOID.LOCALITY_NAME, 'Brno'),
        utils.x509.NameAttribute(utils.NameOID.ORGANIZATION_NAME, 'University of Technology'),
        utils.x509.NameAttribute(utils.NameOID.COMMON_NAME, 'CA-vut.cz'),
        utils.x509.NameAttribute(utils.NameOID.EMAIL_ADDRESS, 'CA@vut.cz'),
    ])


class CA:
    def __init__(self):
        """
            generating of RSA keys for CA
        """
        self.private_key, self.public_key = utils.generate_cryptography_rsa_keys()
        self.ss_certificate = self.create_self_signed_certificate()
        self.connection = socket.socket()
        self.list_of_certs = []

    def create_certificate_from_request(self, request: utils.x509.CertificateSigningRequest):
        """
            before creating a certificate we initialize the subject(user) and issuer(ca)
            :param request: certificate request
            :return: returns created certificate
        """
        now = datetime.datetime.utcnow()
        subject_name = request.subject
        issuer_name = fill_certificate_name()
        certificate = utils.x509.CertificateBuilder() \
            .subject_name(subject_name) \
            .issuer_name(issuer_name) \
            .public_key(request.public_key()) \
            .serial_number(utils.x509.random_serial_number()) \
            .not_valid_before(now) \
            .not_valid_after(now + datetime.timedelta(days=1)) \
            .sign(self.private_key, utils.hashes.SHA256(), utils.default_backend())
        return certificate

    def create_self_signed_certificate(self):
        """
            used to create request for the self signed certificate,
            sign() functions fill the request with public key that's why we dont use the .public_key() method
            :return: returns a self signed certificate
        """
        request = utils.x509.CertificateSigningRequestBuilder() \
            .subject_name(fill_certificate_name()) \
            .sign(self.private_key, utils.hashes.SHA256(), utils.default_backend())
        return self.create_certificate_from_request(request)

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
                except utils.InvalidSignature:
                    print('Verification of the request failed ')
                    utils.send_data(self.connection, b'verification failed', 'verification failed')
                    continue
            if data == b'requesting your public key':
                self.send_my_certificate()
            if data == b'fin':
                utils.send_acknowledgement(self.connection)
                print('ending connection, the same port can be used again')
                self.connection.close()
                break

    def send_certificate(self):
        """
            first we convert the certificate request form PEM to x509 format, create the certificate and
            send the certificate and the signature back to the user
        """
        print('ready to accept, sending ack')
        utils.send_acknowledgement(self.connection)
        data = utils.receive_data(self.connection, 'cert req')
        request = utils.x509.load_pem_x509_csr(data, utils.default_backend())
        request.public_key().verify(
            request.signature,
            request.tbs_certrequest_bytes,
            utils.padding.PKCS1v15(),
            request.signature_hash_algorithm
        )
        cert = self.create_certificate_from_request(request)
        self.list_of_certs.append(cert)
        pem_cert = cert.public_bytes(utils.PEM)
        utils.send_data(self.connection, pem_cert, 'cert')

    def send_my_certificate(self):
        """
            send self signed certificate to the user for verification
        """
        utils.send_acknowledgement(self.connection)
        pem_public_key = self.ss_certificate.public_bytes(utils.PEM)
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
