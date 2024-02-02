import struct
import base64

class parsePacket:
    def __init__(self, data: bytes):
        self.raw_data = data

        dst, src, p_type, mode, pktnum, datalen, checksum = struct.unpack('! 4s 4s s B I I I', self.raw_data[:22])

        self.dst = self.formatIpv4(dst)
        self.src = self.formatIpv4(src)
        self.p_type = p_type.decode()
        self.mode = mode
        self.pktnum = pktnum
        self.datalen = datalen#ord(datalen.decode())
        try:
            self.data = self.raw_data[22:].decode()
        except UnicodeDecodeError:
            self.data = base64.b64encode(self.raw_data[22:])
        self.checksum = checksum

    def varify_checksum(self):
        if self.checksum == len(self.raw_data[:18] + self.raw_data[22:]):
            return True
        return False

    def formatIpv4(self, ip):
        return '.'.join(map(str, ip))

    def print_data(self):
        print(self.dst, self.src, self.p_type, self.mode, self.pktnum, self.datalen,  self.checksum, self.data)

