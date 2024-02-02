import test_proto
import parsePacket
import random
import secrets
import pgp_handler
from cryptography.fernet import Fernet
#use AES-GCM
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


    def generateSymetricKey(self):
        return secrets.token_urlsafe(256)
    
    def encrypt(self, data: str) -> bytes:
        key = self.symetric_key
        f = Fernet(key)
        return f.encrypt(bytes(data, 'utf-8'))
    
    def decrypt(self, data: bytes) -> bytes:
        key = self.symetric_key
        f = Fernet(key)
        return f.decrypt(data)

    def clienttBridge(self, priv, sec):
        ##this will start the handshake
        clientPublic = test_proto.test_proto(self.server, self.client, "C", 1, self.packet_num, self.public_key)
        clientPublic.formatFullData()
        self.socket.send(clientPublic.full_data)
        self.packet_num += 1
        import time
        time.sleep(.5)


        expectedServerPublicKey = self.socket.recv(10000)
        #print(expectedServerPublicKey)
        serverPacket = parsePacket.parsePacket(expectedServerPublicKey)

        #decrypt servers public key
        handle = pgp_handler.pgpHandeler()
        self.server_public_key = handle.decrypt(priv, sec, serverPacket.data)

        print(self.server_public_key)
        if serverPacket.p_type == "S":
            self.symetric_key = self.generateSymetricKey()
            #print(self.symetric_key)
            encrypted_data = handle.encrypte(self.server_public_key, self.symetric_key)

            encrypted_packet = test_proto.test_proto(self.server, self.client, "E", 1, self.packet_num, encrypted_data)
            encrypted_packet.formatFullData()
            self.socket.send(encrypted_packet.full_data)
            self.packet_num += 1


    def serverBridge(self, priv, key):
        expectedCilentPublicKey = self.socket.recv(10000)
        if expectedCilentPublicKey:
            clientRequest = parsePacket.parsePacket(expectedCilentPublicKey)
            if clientRequest.p_type == "C":
                self.client_public_key = clientRequest.data

                encrypted_public_key = 1
                #print(self.client_public_key)
                handle = pgp_handler.pgpHandeler()
                respondToClient = handle.encrypte(self.client_public_key, self.public_key)#encrypt server public key with client public key

                
                serverPublic = test_proto.test_proto(self.server, self.client, "S", 1, self.packet_num, respondToClient)
                serverPublic.formatFullData()
                self.socket.send(serverPublic.full_data)
                self.packet_num += 1

                expectedEncryptionPacket = self.socket.recv(10000)
                serverEncryptionPacket = parsePacket.parsePacket(expectedEncryptionPacket)
                if serverEncryptionPacket.p_type == "E":
                    self.symetric_key = handle.decrypt(priv, key, serverEncryptionPacket.data)
                    print(self.symetric_key)
