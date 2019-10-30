from methods import *
import sys


class CA:
    def __init__(self):
        self.keys, self.public_key = create_keys()
        self.list_of_certs = []
        self.send_cert()

    def create_cert(self, request):
        # https://en.wikipedia.org/wiki/Public_key_certificate#Common_fields

        if request.verify(request.get_pubkey()):
            cert = crypto.X509()
            cert.set_serial_number(1000)
            cert.get_subject().countryName = "CZ"
            cert.get_subject().stateOrProvinceName = "Czech Republic"
            cert.get_subject().localityName = "Brno"
            cert.get_subject().organizationName = "University of Technology"
            cert.get_subject().organizationalUnitName = "FEKT"
            cert.get_subject().commonName = "user1-fekt.cz"
            cert.get_subject().emailAddress = "user1@fekt.cz"
            cert.set_issuer(request.get_subject())
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(60 * 60 * 24)
            cert.set_pubkey(request.get_pubkey())
            cert.sign(self.keys, "sha256")
            self.list_of_certs.append(cert)
            return cert

    def send_cert(self):
        port = int(input("listen port : "))
        print("listening for anything")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((LOCALHOST, port))
        s.listen()
        conn, addr = s.accept()
        print('connected to {}'.format(addr))
        while True:
            data = conn.recv(2048)
            if data == b'1':
                print('starting 01')
                conn.send(b'ack')
                data = conn.recv(2048)
            if data == b'sending request':
                print('sending cert from req')
                conn.send(b'ack')
                data = conn.recv(2048)
                cert_req = crypto.load_certificate_request(crypto.FILETYPE_PEM, data)
                cert = self.create_cert(cert_req)
                data_to_send = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                conn.send(data_to_send)
                wait_for_ack(conn)

            if data == b'fin':
                conn.send(b'ack')
                print('ending connection')
                conn.close()
                break


ca = CA()
while True:
    ca.send_cert()