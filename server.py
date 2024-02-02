import socket
import test_proto
import parsePacket
import random
import secrets
import pgp_handler
from cryptography.fernet import Fernet
import base64
import time



class Bridge:
    #bidirectinal client/server
    #will use PGP for asymetric key exchange
    THREE_WAY = {1:"C", 2:"S", 3:"E"}


    def __init__(self, socket, server, client, public_key):
        self.step = 0
        self.socket = socket 
        self.server = server #dst
        self.client = client #src
        self.symetric_key = None
        self.public_key = public_key
        self.client_public_key = None
        self.server_public_key = None
        self.packet_num = 0

    def generate_session_id(self) -> str:
        return ''.join([str(random.randint(0,10)) for _ in range(10)])


    def generateSymetricKey(self) -> bytes:
        return secrets.token_bytes(32)#token_urlsafe(32)#token_bytes(32)
    
    def encrypt(self, data: str):
        key = bytes(base64.urlsafe_b64encode(self.symetric_key))#self.symetric_key
        f = Fernet(key)
        byte_data = f.encrypt(bytes(data, 'utf-8'))
        byte_data = str(byte_data)
        bindata = ''.join([str(x) for x in byte_data[2:-1]])#base64.b64decode(''.join([str(x) for x in byte_data[2:-1]]))
        encrypted_packet = test_proto.test_proto(self.server, self.client, "W", 1, 0, bindata)#f.encrypt(bytes(data, 'utf-8')))
        encrypted_packet.formatFullEncData()
        self.socket.send(encrypted_packet.full_data)
        self.packet_num += 1
        time.sleep(1)

    def decrypt(self, data: bytes) -> bytes:
        serverPacket = parsePacket.parsePacket(data)
        if not serverPacket.varify_checksum():
            exit()
        key = bytes(base64.urlsafe_b64encode(self.symetric_key))#base64.urlsafe_b64decode(str(self.symetric_key))#bytes(self.symetric_key)
        f = Fernet(key)
        return f.decrypt(serverPacket.data).decode()

    def clienttBridge(self, priv, sec):
        ##this will start the handshake
        clientPublic = test_proto.test_proto(self.server, self.client, "C", 1, self.packet_num, self.public_key)
        clientPublic.formatFullData()
        self.socket.send(clientPublic.full_data)
        self.packet_num += 1
        time.sleep(.5)


        expectedServerPublicKey = self.socket.recv(10000)
        #print(expectedServerPublicKey)
        serverPacket = parsePacket.parsePacket(expectedServerPublicKey)
        if not serverPacket.varify_checksum():
            exit()

        #decrypt servers public key
        handle = pgp_handler.pgpHandeler()
        self.server_public_key = handle.decrypt(priv, sec, serverPacket.data)

        if serverPacket.p_type == "S":
            self.symetric_key = self.generateSymetricKey()
            encrypted_data = handle.encrypte(self.server_public_key, self.symetric_key)
            encrypted_packet = test_proto.test_proto(self.server, self.client, "E", 1, self.packet_num, encrypted_data)
            encrypted_packet.formatFullData()
            self.socket.send(encrypted_packet.full_data)
            self.packet_num += 1



    def serverBridge(self, priv, key):
        expectedCilentPublicKey = self.socket.recv(10000)
        if expectedCilentPublicKey:
            clientRequest = parsePacket.parsePacket(expectedCilentPublicKey)
            if not clientRequest.varify_checksum():
                exit()

            if clientRequest.p_type == "C":
                self.client_public_key = clientRequest.data

                  #print(self.client_public_key)
                handle = pgp_handler.pgpHandeler()
                respondToClient = handle.encrypte(self.client_public_key, self.public_key)#encrypt server public key with client public key

                    
                serverPublic = test_proto.test_proto(self.server, self.client, "S", 1, self.packet_num, respondToClient)
                serverPublic.formatFullData()
                self.socket.send(serverPublic.full_data)
                self.packet_num += 1

                expectedEncryptionPacket = self.socket.recv(10000)
                serverEncryptionPacket = parsePacket.parsePacket(expectedEncryptionPacket)
                if not serverEncryptionPacket.varify_checksum():
                    exit()

                if serverEncryptionPacket.p_type == "E":
                    #print(serverEncryptionPacket.data)
                    self.symetric_key = handle.decrypt(priv, key, serverEncryptionPacket.data)





pub = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v2.0.76
Comment: https://keybase.io/crypto

xo0EZNaWWwEEAJmRge5/1rTTXF7WIfENfofDE1ttGKPyCiYRKIWTX3JABLlAJ3NE
gFN64XKJ0eFmM0qkH8VFYabD48gczqlATWRUW8YpKOPuCRPw+acGnWR1JDF80qXc
RsQgvSz30gZmjZ9C52+Y+4wGzswVMtGUH7visuzVZPgsM66tE7bvvaFJABEBAAHN
GG1pY2hhZWwgPHRlc3RAZ21haWwuY29tPsK6BBMBCgAkBQJk1pZbAhsvAwsJBwMV
CggCHgECF4ADFgIBAhkBBQkB4TOAAAoJEMa/Kwg7hBIauQED/3mm5d0hwqEZx6RP
2RnRcAPI/qk6gcPghWYB5HHD0hr2PiXY/rY77WOe46vAXh0qINASRSahLt9XCWmR
EuVYB72RBPn+JSaK4kJKJAYPDVz2dcWCL8EW5QSBxcJDslSCOwEMT5HXLihfE1fq
vOaMeEaTNmY98bZRwAROkFzhPQinzo0EZNaWWwEEAPduS5ydOJtAGj91QRxGXPXH
OyD3XwO7xRutwFzq1bliSd6va79L7f7FH30LSt1QTTw+QOa+3+KC1I+T0nAZfFVM
caDVz0S+0OEN1yOhuwakre06iuxY/NiuI+LiY5VLB6YZAE++w0Mf3SwezbyT907d
C11WqPIyLjK8HE/MkAvfABEBAAHCwIMEGAEKAA8FAmTWllsFCQHhM4ACGy4AqAkQ
xr8rCDuEEhqdIAQZAQoABgUCZNaWWwAKCRBietmtI1dJUl3ZA/sFymq622mEV6FT
t+CByvaXq0K++EKokZQ0nbn9iE39l4KAqyZwZMmJw1NMfHDku6BLC/DCsL4RH5QV
K6uyg2u3/lZJGtwXkENZ8mKXAEI4ZGQq5aUZZv5xt1k02wWi2juvMLwbbjxarZSw
5Fccn1UJn7MKmmVu6Z268SX+szZAcqL0A/9B9JrAd2ZqPxjmENrvdSnM8mtyVusY
E20n6SNaDIgsXsibIz76+afD8fRnUMxc6AQaauagaVZ/3stmNWK/U/jfhU+92xLI
9vQd7Y5vgVdWxVizZ5aAPQJDkQ71ruYRoeTdVDvQ7E8O6TV0FQpBUvo9+IoWMJ0Y
EDkFxgiuDM99Zs6NBGTWllsBBACmxGIM/MGsryqoukluwfYe418+cjVe5bvBnUbm
uUIYWWqgGz6OcQNj5pG9MZ/vVSNrD/qyum5KoQmjcveXcsg8n4BcL6JbWun+4V46
GBqFjZc4H2QFFbNVjtYDgjH/+qmbPjYFBys2VDX0UOkm0J6kmJYtjuOdeboKVngH
6v1WnwARAQABwsCDBBgBCgAPBQJk1pZbBQkB4TOAAhsuAKgJEMa/Kwg7hBIanSAE
GQEKAAYFAmTWllsACgkQl7ssotSDbaB+FAQAmHPP1PxWhScz7Wpd03/VRnfYyhYr
mzXh9oHHfziVna/HTU+kJvoQdb7kOqwaJrtmyboyiduTwpwgzpH9dPwT4HRTv6dn
8ZuuMN+3IjF79XViYjjXninyKeOXpm1HudSSYKc0dvQvh4CbhkxlnPxJcBaEik3c
5jxOrf5dCFQ6c1ZsGwQAg5DtTSKwpoQaWWLRBzONgcprse0LoprIFLOO+cJNFga6
2nubMvzb3YyeLfNfvxEx4s6RZJvPqZ1lWyT7DwYq/owSLE7i2T/r35LEniyHcPgz
dK0peK1ju450L7v4unyLKZ+eGWr1EOG6Thh2RF10ukG60cE+qtIb9YokW3QKbyU=
=dAn1
-----END PGP PUBLIC KEY BLOCK-----"""
priv = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v2.0.76
Comment: https://keybase.io/crypto

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
avUQ4bpOGHZEXXS6QbrRwT6q0hv1iiRbdApvJQ==
=+Rmi
-----END PGP PRIVATE KEY BLOCK-----
"""

key = "jM5D5Ud@!Qxsn5y"
host = socket.gethostbyname(socket.gethostname())
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



s.bind((host, 9999))
s.listen(5)
clientsocket, address = s.accept()

brid = Bridge(clientsocket, "9.9.9.9", "9.9.9.9", pub)
brid.serverBridge(priv, key)

while True:
    encrypted_msg = brid.socket.recv(10000)
    
    if encrypted_msg:
        print(brid.decrypt(encrypted_msg))
    