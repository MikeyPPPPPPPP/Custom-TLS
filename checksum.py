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

    
    def formatFullData(self) -> bytearray:
        try:
            datalen = struct.pack('!i', len(self.data))
        except TypeError:
            datalen = struct.pack('!i', 1)

        pktnum = struct.pack('!i', self.pktnum)
        checksum = len(self.formatToipv4(self.dst) + self.formatToipv4(self.src) + self.strTobytearray(self.p_type) + bytearray([self.mode]) + pktnum + datalen + self.strTobytearray(self.data))

        checksum = struct.pack('!i', checksum)
        
        self.full_data = self.formatToipv4(self.dst) + self.formatToipv4(self.src) + self.strTobytearray(self.p_type) + bytearray([self.mode]) + pktnum + datalen + checksum + self.strTobytearray(self.data)



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
        self.data = self.raw_data[22:].decode()
        self.checksum = checksum

    def formatIpv4(self, ip):
        return '.'.join(map(str, ip))

    def print_data(self):
        print(self.dst, self.src, self.p_type, self.mode, self.pktnum, self.datalen,  self.checksum, self.data)


    def varify_checksum(self):
        if self.checksum == len(self.raw_data[:18] + self.raw_data[22:]):
            return True
        return False

t = test_proto("1.1.1.1", "1.1.1.1", "C", 1, 0, "gdfsgd")
t.formatFullData()
d = t.full_data
print(d)
s = parsePacket(d)
print(s.varify_checksum())



