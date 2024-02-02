import struct

class test_proto:
    def __init__(self, dst, src, p_type, mode, pknum, data):
        self.full_data = ""

        self.dst = dst
        self.src = src
        self.p_type = p_type
        self.mode = mode
        self.pktnum = pknum
        self.checksum = 0
        self.datalen = 0
        self.data = data

    def formatToipv4(self, ipv4_addr: str) -> bytearray:
        ip = ipv4_addr.split('.')
        return struct.pack('!BBBB',int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))

    def strToInt(self, data: str) -> int:
        return struct.pack('!B', data)

    
    def strTobytearray(self, data):

        edata = str(len(str(data))).encode()
        strlen = edata.decode() + 's'

        return struct.pack(strlen, str(data).encode())

    def base64ToBytes(self, data):
        import base64
        return base64.urlsafe_b64decode(data)
    
    def formatFullEncData(self) -> bytearray:
        try:
            datalen = struct.pack('!i', len(self.data))
        except TypeError:
            datalen = struct.pack('!i', 1)
        pktnum = struct.pack('!i', self.pktnum)
        checksum = len(self.formatToipv4(self.dst) + self.formatToipv4(self.src) + self.strTobytearray(self.p_type) + bytearray([self.mode]) + pktnum + datalen + self.base64ToBytes(self.data))
        checksum = struct.pack('!i', checksum)
        self.full_data = self.formatToipv4(self.dst) + self.formatToipv4(self.src) + self.strTobytearray(self.p_type) + bytearray([self.mode]) + pktnum + datalen + checksum + self.base64ToBytes(self.data)
    
    def formatFullData(self) -> bytearray:
        try:
            datalen = struct.pack('!i', len(self.data))
        except TypeError:
            datalen = struct.pack('!i', 1)

        pktnum = struct.pack('!i', self.pktnum)
        checksum = len(self.formatToipv4(self.dst) + self.formatToipv4(self.src) + self.strTobytearray(self.p_type) + bytearray([self.mode]) + pktnum + datalen + self.strTobytearray(self.data))

        checksum = struct.pack('!i', checksum)
        
        self.full_data = self.formatToipv4(self.dst) + self.formatToipv4(self.src) + self.strTobytearray(self.p_type) + bytearray([self.mode]) + pktnum + datalen + checksum + self.strTobytearray(self.data)
