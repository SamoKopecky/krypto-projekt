from methods import *


def create_request():
    keys, public_key = create_keys()
    request = crypto.X509Req()
    request.get_subject().countryName = "EN"
    request.get_subject().stateOrProvinceName = "Czech Republic"
    request.get_subject().localityName = "Brno"
    request.get_subject().organizationName = "University of Technology"
    request.get_subject().organizationalUnitName = "FEKT"
    request.get_subject().commonName = "user1-fekt.cz"
    request.get_subject().emailAddress = "user1@fekt.cz"
    request.set_pubkey(public_key)
    request.sign(keys, "sha256")
    return request


def finish_conn(s):
    s.send(b'fin')
    wait_for_ack(s)
    print('ending comunictaion')
    s.close()


class User:

    def __init__(self):
        self.cert = crypto.X509()
        self.port = int(input('choose port : '))

    def send_ca_request(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((LOCALHOST, self.port))
        print("seding request to start communication")
        s.send(b'1')
        wait_for_ack(s)
        s.send(b'sending request')
        data_to_send = crypto.dump_certificate_request(crypto.FILETYPE_PEM, create_request())
        s.send(data_to_send)
        print('request sent')
        wait_for_ack(s)
        data = s.recv(2048)
        print('cert recieved')
        s.send(b'ack')
        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        finish_conn(s)


user = User()
user.send_ca_request()
print(user.cert.get_subject().C)
input()
# pem_cert = ca.create_cert(requ9est)
# cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
# need to finish verify
