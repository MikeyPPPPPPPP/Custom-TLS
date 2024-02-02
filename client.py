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


    def generateSymetricKey(self):
        return secrets.token_bytes(32)#token_urlsafe(32)#token_bytes(32)
    
    def encrypt(self, data: str) -> bytes:
        key = bytes(base64.urlsafe_b64encode(self.symetric_key))#self.symetric_key
        f = Fernet(key)
        byte_data = f.encrypt(bytes(data, 'utf-8'))
        byte_data = str(byte_data)
        bindata = ''.join([str(x) for x in byte_data[2:-1]])#base64.b64decode(''.join([str(x) for x in byte_data[2:-1]]))
        encrypted_packet = test_proto.test_proto(socket.gethostbyname(socket.gethostname()), socket.gethostbyname(socket.gethostname()), "W", 1, 0, bindata)#f.encrypt(bytes(data, 'utf-8')))
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
        import time
        time.sleep(.5)


        expectedServerPublicKey = self.socket.recv(10000)
        #print(expectedServerPublicKey)
        serverPacket = parsePacket.parsePacket(expectedServerPublicKey)
        if not serverPacket.varify_checksum():
            exit()

        #decrypt servers public key
        if serverPacket.p_type == "S":
            handle = pgp_handler.pgpHandeler()
            self.server_public_key = handle.decrypt(priv, sec, serverPacket.data)

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

xo0EZNaWxgEEAJfYTwRqke6XJkZSmLWQ7OOR8s8jvPyxzp23xASwpadH12EHsQuM
mtx7bzktfVvu/hdtECIewLKnL5QGjRUOGmWrfxr/x1vssFEoeLpftc3NOW05Zjxb
Q7AZcAAbZJ7oau/k23Il2WZqlb3/pPwmFSNlhJBRx7LJPieFcQQKbnevABEBAAHN
HW1pY2hhZWwyIDxmYXNkZnNAZ2RzYWYuc2Rjc2Q+wroEEwEKACQFAmTWlsYCGy8D
CwkHAxUKCAIeAQIXgAMWAgECGQEFCQHhM4AACgkQidQ/6qduNP6hIAP/VadnOt9y
rrXyCEsDjfzSqFpbpUra3OdTd9rLNkDQYOBBumoc8P/MNKAaylJEi5KixG0jIkWD
cnFHiZPf7CZcefHdCyWGDdnecm7/W7UwBbdP9VXPb0xeByb7tk6+Ox6gAItlZv84
VfT/ENbJGlmhBUVCBMIsbwTtssoqzza7+r/OjQRk1pbGAQQAvedhSI3aLsEueGZy
BUKVOwmo6871NNqOSKQe3oLKnvSsKqS0G9Blq6g+gVB786OSiJ3SYvlSNl//wVd5
AmRQR4l2FMqrQVRhZMNPRuN5lJRyXDr+PGujOiKdy6Dhi51pjYTleNkTPUdkjbBX
zQKhd+7DesrLSOuOuC/76qrnKGMAEQEAAcLAgwQYAQoADwUCZNaWxgUJAeEzgAIb
LgCoCRCJ1D/qp240/p0gBBkBCgAGBQJk1pbGAAoJEIYK55H+qr566rAEALmR+OiO
5/P2PlsDD6BT0YU5UQT9Hqb8i8tC1Y7x2eS9p9m39lCGAoQb3msd0qmDyLZE6p4E
sGMFvtgZuBcJdPvu7y/VTA4TTt5eCuio5SPW/kcrpvjMO8WoQUdu2WzdLQJVs4Hm
EPiTf8gbi/yBLe7O68z1f+hsKIe5VgTezMkN+KQD/2b+KfKlURbASj49yEScDwRM
uKIvxGGrV4EsDwN6ftfW97pMxHxpcNUDCtP4f6eN8P861OW9wzTRIysc5eYbHS5M
Gxk+XpO6AW3tMPYu/Wr2n8a86AU/kveZPVSFxBzzGglg9E4i3NeYlKV4k/vrYQVu
Y7zyPJnNxcNKx2G3NPCFzo0EZNaWxgEEANLb2ra1iiEdqnA+hYP6GtSaMX83rgtC
B3fV6TQZzDKAm+zFdnYVJipoQRkHrMmzqE8F2FAD7oqbm00MmbL/m2DGvl5S4HnD
YGzRseCcIp1zf58Bhd9IeSHgFPNvmsknhXNDglPk6oopOcnl8vQ7nK073ZM0zLHV
NKV7BpJJp3OzABEBAAHCwIMEGAEKAA8FAmTWlsYFCQHhM4ACGy4AqAkQidQ/6qdu
NP6dIAQZAQoABgUCZNaWxgAKCRBLALv5zw8O98GLBACr1wyfLcR1m/P1SmuCV/dJ
bwSu3pDgl1N4u6hTDq0Atz6/b/TCb79QQAlKjFOQo98xTUn68dV5xAUZUqWTlXgE
IrjmmkMx3rVJWyXIND8+wdSAkjS7JwjOHjkuas3tpG6RO2aMiEE3+AniwgqGbq7H
kzBGf8g70L1InEDpWkl18cFKA/9bvmOp8IDMtiJHnSpWIARcWlTmiv00hO8+uu8v
/+W1AYzuADUnGLiM4SFBaXi/2gFUNvngNmAQ5uiHmY6/2tA6vEXBygMREZoVcG9N
/PIBy01epA/CVFSNKBVIj9ig2qpFEAiFUBiPaLC2mPycpmAcs6AVdcPS6RCJEAac
5XluOQ==
=lKML
-----END PGP PUBLIC KEY BLOCK-----
"""
priv = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v2.0.76
Comment: https://keybase.io/crypto

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
=3sTN
-----END PGP PRIVATE KEY BLOCK-----
"""
key = "t9RtTRPPE@@3uUh"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostbyname(socket.gethostname())
s.connect((host, 9999))



brid = Bridge(s, socket.gethostbyname(socket.gethostname()), socket.gethostbyname(socket.gethostname()), pub)
brid.clienttBridge(priv, key)


brid.encrypt("secret text")

brid.encrypt("This is a new text packet that should be encrypted")

