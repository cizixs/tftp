import sys
import socket
import struct
import binascii
import argparse

MAXSIZE = 500
PORT = 6699

# Protocol type
RRQ = 1
WRQ = 2
DATA = 3
ACK = 4
ERROR = 5


class State(object):
    START, DATA = range(2)


# Make packet functions. 
# Client only handles 4 packets.
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

def make_ack_packet(block_num):
    return struct.pack('!H H', ACK, block_num)


class TftpClient(object):
    def __init__(self, host='127.0.0.1', port=PORT, filename=None, **argv):
        self.host = host
        self.port = port
        self.block_size = 512
        self.block_num = 1
        self.is_done = False
        self.status = State.START
        self.action = 'get'
        self.filename = filename
        self.setup_file()
        self.setup_connect()

    @property
    def server_addr(self):
        return (self.host, self.port)

    @property
    def max_packet_size(self):
        return self.block_size + 4

    def setup_file(self):
        if self.filename:
            if self.action == 'get':
                self.fd = open(self.filename, 'wb')
            elif self.action == 'put':
                self.fd = open(self.filename, 'rb')
            else:
                raise Exception('unsupport action %s' % self.action)

    def setup_connect(self):
        """Socket setup.
        Because UDP is connectionless, just create a UDP socket.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_packet(self, packet):
        """Send packet to remote server."""
        self.sock.sendto(packet, self.server_addr)

    def recv_packet(self):
        """Receive packet from remote server.

        By default, `sock.recvfrom` is blocking, which might cause 
        performance problem. Use select to handle over CPU while waiting.

        Also, if waiting timeout, return (None, None).
        """
        (packet, addr) = self.sock.recvfrom(self.max_packet_size)
        return (packet, addr)

    def handle_packet(self, packet, addr):
        """Handle pakcet from remote.

        If it's a wrong packet, not from expected host/port, discard it;
        If it's a data packet, send ACK packet back;
        If it's a error packet, print error and exit;
        If it's a ack packet, send Data packet back.
        """
        host, port = addr
        if host != self.host:
            # ignore packet from wrong address.
            return

        packet_len = len(packet)

        opcode = struct.unpack('!H', packet[:2])[0]
        if opcode == ERROR:
            err_code = struct.unpack('!H', packet[2:4])[0]
            err_msg = packet[4:packet_len-1]
            print "Error %s: %s" % (err_code, err_msg)
            sys.exit(err_code)
        elif opcode == DATA:
            # This is a data packet received from server, save data to file.

            # update port
            if self.port != port:
                self.port = port
            block_num = struct.unpack('!H', packet[2:4])[0]
            if block_num != self.block_num:
                # skip unexpected #block data packet 
            	return
            data = packet[4:]
            self.fd.write(data)
            if len(packet) < self.block_size + 2:
                self.is_done = True
                self.fd.close()
                file_len = self.block_size * (self.block_num -1) + len(data)
                print '%d bytes received.' % file_len 
            ack_packet = make_ack_packet(self.block_num)
            self.send_packet(ack_packet)
            self.block_num += 1
        elif opcode == ACK:
            # This is a write request ACK
            raise NotImplementedError('Put action is not supported right now.')
        else:
            raise Exception('unrecognized packet: %s', str(opcode))
        
    def get_next_packet(self):
        if self.status == State.START:
            opcode = RRQ if self.action == 'get' else WRQ
            packet = make_request_packet(opcode, self.filename)
            self.status = State.DATA
        elif self.status == State.DATA:
            if self.action == 'get':
                packet = make_ack_packet(self.block_num-1)
            elif self.action == 'put':
                data = self.fd.read(self.block_size)
                packet = make_data_packet(self.block_num, data)

        return packet

    def handle(self):
        """Main loop function for tftp.
        
        The main loop works like the following:
        1. get next-to-send packet
        2. send the packet to server
        3. receive packet from server
        4. handle packet received, back to step 1.
        """
        while not self.is_done:
            packet = self.get_next_packet()
            if packet:
                self.send_packet(packet)
            (packet, addr) = self.recv_packet()
            self.handle_packet(packet, addr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Argparser for tftp.')
    parser.add_argument('-s', action='store', dest='host', 
            default='127.0.0.1', help='Server hostname')
    parser.add_argument('-p', action='store', dest='port', type=int,
            default=69, help='Server port')
    parser.add_argument('-f', action='store', dest='filename', 
            default='test.txt', help='File to get from server')
    result = parser.parse_args()

    tftp = TftpClient(result.host, result.port, result.filename)
    tftp.handle()
