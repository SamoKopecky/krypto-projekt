import utils


class CA:
    def __init__(self):
        self.private_key, self.public_key = utils.generate_openssl_keys()  # vytvorenie RSA klucov
        self.list_of_certs = []

    def create_cert(self, request):
        # https://en.wikipedia.org/wiki/Public_key_certificate#Common_fields
        self.verify_cert_request(request)
        cert = utils.crypto.X509()  # vytovrenie x509 certifikatu
        # nastavnie vlastnosti
        cert.set_serial_number(1000)
        cert.get_subject().countryName = 'CZ'
        cert.get_subject().stateOrProvinceName = 'Czech Republic'
        cert.get_subject().localityName = 'Brno'
        cert.get_subject().organizationName = 'University of Technology'
        cert.get_subject().organizationalUnitName = 'VUT'
        cert.get_subject().commonName = 'CA-vut.cz'
        cert.get_subject().emailAddress = 'CA@vut.cz'
        # issuer je host
        cert.set_issuer(request.get_subject())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24)  # 24 hodin je planty certfikat
        cert.set_pubkey(request.get_pubkey())
        cert.sign(self.private_key, 'sha256')
        self.list_of_certs.append(cert)
        return cert

    def verify_cert_request(self, request):
        pass  # TODO

    def listen_for_cert_req(self, port):  # funkcia ktora stale bezi a pocuva na portoch ktorych si zvolime
        connection, address = utils.start_listening(port)  # zacatie komunikacie, vrati name socket(connection)
        while True:
            data = connection.recv(2048)  # ukladanie dat po castiach velkych 2048 bajtov
            if data == b'sending cert request':  # ak je user pripraveny posielat ziadost o certifikat
                print('ready to accept, sending ack')
                utils.send_ack(connection)  # autorita posiela acknowledgement(suhlas o tom ze dostal spravu)
                data = utils.receive_data(connection, 'cert req')  # prima data od usera
                # prekonvertuje PEM format na format x509 request
                cert_req = utils.crypto.load_certificate_request(utils.PEM_FORMAT, data)
                cert = self.create_cert(cert_req)  # vytvori certifikat
                data_to_send = utils.crypto.dump_certificate(utils.PEM_FORMAT, cert)  # konvertuje na PEM format
                utils.send_data(connection, data_to_send, 'cert')  # posle PEM format certifikatu
            if data == b'fin':  # ak user chce ukoncit spojenie
                utils.send_ack(connection)
                print('ending connection, the same port can be used again')
                connection.close()  # ukoncenie spojenia na porte
                break

            # verify function for certificate


def use_ca():
    ca = CA()
    port = int(input('choose port to listen to : '))  # uzivatel si zvoli port
    while True:
        ca.listen_for_cert_req(port)


use_ca()
