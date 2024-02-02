


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
        edata = str(len(data)).encode()
        strlen = edata.decode() + 's'

        return struct.pack(strlen, data.encode())

    
    def formatFullData(self) -> bytearray:
        datalen = struct.pack('!i', len(self.data))
        pktnum = struct.pack('!i', self.pktnum)
        checksum = len(self.formatToipv4(self.dst) + self.formatToipv4(self.src) + self.strTobytearray(self.p_type) + bytearray([self.mode]) + pktnum + datalen + self.strTobytearray(self.data))

        checksum = struct.pack('!i', checksum)
        
        self.full_data = self.formatToipv4(self.dst) + self.formatToipv4(self.src) + self.strTobytearray(self.p_type) + bytearray([self.mode]) + pktnum + datalen + checksum + self.strTobytearray(self.data)



a = test_proto("192.168.86.1", "192.168.86.1", "A", 1, 0, "test this is a great")
a.formatFullData()
print(a.full_data)
print(a.p_type_set(b"SPK"))



class parsePacket:
    def __init__(self, data: bytes):
        self.raw_data = data


        self.dst = None
        self.src = None
        self.p_type = None
        self.mode = None
        self.pktnum = None
        self.checksum = None
        self.datalen = None
        self.data = None

    def formatIpv4(self, ip):
        return '.'.join(map(str, ip))

    def parseDstSrc(self):
        #src, p_type, mode, pktnum, checksum, datalen, data 
        dst, src, p_type, mode, pktnum, datalen, checksum = struct.unpack('! 4s 4s s B I I I', self.raw_data[:22])
        #checksum  = struct.unpack('! I', self.raw_data[-4:])
        self.dst = self.formatIpv4(dst)
        self.src = self.formatIpv4(src)
        self.p_type = p_type.decode()
        self.mode = mode
        self.pktnum = pktnum
        self.datalen = datalen#ord(datalen.decode())
        self.data = self.raw_data[22:].decode()
        self.checksum = checksum
    
    def print_data(self):
        print(self.dst, self.src, self.p_type, self.mode, self.pktnum, self.datalen,  self.checksum, self.data)



s = parsePacket(a.full_data) 
s.parseDstSrc()
#s.print_data()



