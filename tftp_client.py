import socket
import struct

MAXSIZE = 500

RRQ = 1
WRQ = 2
DATA = 3
ACK = 4
ERROR = 5

def make_request_packet(opcode, filename):
    mode = 'octet'
    values = (opcode, filename, 0, mode, 0)
    s = struct.Struct('! H {}s B {}s B'.format(len(filename),len(mode)) )
    return s.pack(*values)
    
def make_rrq_packet(filename):
    return make_request_packet(RRQ, filename)

def make_wrq_packet(filename):
    return make_request_packet(WRQ, filename)

def make_data_packet(block_num, data):
    return struct.pack('! H H', DATA, block_num) + data


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = make_rrq_packet('test.txt')
    server = ("127.0.0.1", 69)
    s.sendto(msg, server)
    data, addr = s.recvfrom(MAXSIZE)
    print data


if __name__ == "__main__":
	main()
