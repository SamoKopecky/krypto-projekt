import os
import utils


class User:

    def __init__(self):
        self.aes_key = None  # vytvorenie vlastnosti aby sme neskorsie do nej mohli ukladat
        self.aes_iv = None  # to ise ale pre https://en.wikipedia.org/wiki/Initialization_vector
        self.cipher = None
        self.my_cert = utils.crypto.X509()  # vytvorenie premenej pre certifikat typu x509
        # vytvorenie klucov pre rsa z kniznice cryptography
        self.private_key, self.public_key = utils.generate_cryptography_keys()
        self.other_cert = utils.crypto.X509()  # premena pre certifikat druheho usera
        self.other_public_key = utils.rsa.RSAPublicKey  # verejny kluc druheho usera
        self.active_socket = utils.socket.socket()  # soket z ktorym sa komunikuje
        self.name = input('enter your name : ')
        self.received_messages = []

    def create_request(self):  # vytvaranie ziadosti na certifikat
        # konvertovanie RSA klucov z kniznice cryptografy na pyopenssl lebo certifikat je z kniznice pyopenssl
        ssl_public_key = utils.crypto.PKey.from_cryptography_key(self.public_key)
        ssl_private_key = utils.crypto.PKey.from_cryptography_key(self.private_key)
        request = utils.crypto.X509Req()  # vytvorenie objektu typu ziadosti na certifikat
        # tu sa volia len vlastnosti certifikatu
        request.get_subject().countryName = 'CZ'
        request.get_subject().stateOrProvinceName = 'Czech Republic'
        request.get_subject().localityName = 'Brno'
        request.get_subject().organizationName = 'University of Technology'
        request.get_subject().organizationalUnitName = 'VUT'
        request.get_subject().commonName = '{}-vut.cz'.format(self.name)
        request.get_subject().emailAddress = '{}@vut.cz'.format(self.name)
        # nastavenie verejneho kluca z ktoreho vznike certifikat
        request.set_pubkey(ssl_public_key)
        # podpisanie certifikatu
        request.sign(ssl_private_key, 'sha256')
        return request

    def send_ca_request(self):  # v tejto funkcii sa posiela ziadost o certifikat certfikacnej autorite
        client_socket = utils.start_sending()
        # host oznamuje serverovy ze zacne posielat request na certifikat
        utils.send_data(client_socket, b'sending cert request', 'request to start communication')
        # prekonvertuje ziadost na certifikat do PEM formatu
        data_to_send = utils.crypto.dump_certificate_request(utils.PEM_FORMAT, self.create_request())
        utils.send_data(client_socket, data_to_send, 'cert req')  # odoslanie ziadosti
        data = utils.receive_data(client_socket, 'cert')  # prijatie ziadost v PEM formate
        # prekonvertovanie PEM formatu do x509 formatu na ulozenie
        self.my_cert = utils.crypto.load_certificate(utils.PEM_FORMAT, data)
        utils.finish_conn(client_socket)  # ukoncenie spojenia

    def exchange_certs_and_keys(self):
        state = input('listen or send : ')  # volba ci host bude pocuvat alebo posielat ako prvy
        if state == 'listen':
            self.receiving_cert()
            self.receiving_aes_key()
        if state == 'send':
            self.sending_cert()
            self.sending_aes_key()

    def receiving_cert(self):
        connection, address = utils.start_listening()  # zacatie komunikacie
        self.active_socket = connection  # nastavenie socketu cez ktory sa bude komunnikovat
        data = utils.receive_data(self.active_socket, 'cert')
        # nacitanie cudzieho certifikatu z PEM formatu
        self.other_cert = utils.crypto.load_certificate(utils.PEM_FORMAT, data)
        # priprava svojho certifikatu v PEM formate
        data_to_send = utils.crypto.dump_certificate(utils.PEM_FORMAT, self.my_cert)
        utils.send_data(self.active_socket, data_to_send, 'my cert')

    def receiving_aes_key(self):  # primanie aes klucu a iv a potom ulozenie
        key = utils.receive_data(self.active_socket, 'aes key')
        self.aes_iv = utils.receive_data(self.active_socket, 'aes iv')  # iv neni treba desifrovat
        self.aes_key = utils.rsa_decrypt(key, self.private_key)  # desifrovanie kluca

    def sending_cert(self):  # to ise ako receiving_cert ale ako prve host posiela prvy svoj certifikat
        client_socket = utils.start_sending()
        self.active_socket = client_socket
        data_to_send = utils.crypto.dump_certificate(utils.PEM_FORMAT, self.my_cert)
        utils.send_data(self.active_socket, data_to_send, 'my cert')
        data = utils.receive_data(self.active_socket, 'cert')
        self.other_cert = utils.crypto.load_certificate(utils.PEM_FORMAT, data)

    def sending_aes_key(self):
        self.aes_key = os.urandom(32)  # generacia 32 bajtoveho kluca 128 bitov
        self.aes_iv = os.urandom(16)  # generacie 16 bajtoveho vektoru
        # konvertovanie verejneho kluca cudzieho hosta na format cryptography kniznice aby sme z nim mohli sifrovat
        self.other_public_key = utils.convert_key_from_ssl_to_crypt(self.other_cert.get_pubkey())
        data_to_send_1 = utils.rsa_encrypt(self.aes_key, self.other_public_key)
        utils.send_data(self.active_socket, data_to_send_1, 'aes key')
        utils.send_data(self.active_socket, self.aes_iv, 'aes iv')
        # generacia cipheru ktory nam umoznuje sifrovat a desifrovats
        self.cipher = utils.AES.new(self.aes_key, utils.AES.MODE_CBC,self.aes.iv)

    def send_message(self):  # posielanie zasifrovanej zpravy
        message = input('input your message: ')
        utils.aes_encrypt(self.cipher, message)
        utils.send_data(self.active_socket, message, 'encrypted message')

    def receive_message(self):  # prijatie zasifrovanej spravy
        c_message = utils.receive_data(self.active_socket, 'encrypted message')
        message = utils.aes_decrypt(self.cipher, c_message)
        print(message)
        self.received_messages.append(message)

    def start_conversation(self):  # volba posielania alebo primania
        state = input('listen or send : ')
        if state == 'listen':
            self.receive_message()
        if state == 'send':
            self.send_message()


def use_user():  # start usera
    user = User()
    user.send_ca_request()
    user.exchange_certs_and_keys()
    user.start_conversation()


use_user()
