import sys
import struct
import binascii
import argparse

import tftp
from tftp import SocketBase
from tftp import get_opcode
from tftp import make_data_packet
from tftp import make_ack_packet


class State(object):
    START, DATA = range(2)


# Make packet functions. 
def make_request_packet(opcode, filename, mode='octet'):
    values = (opcode, filename, 0, mode, 0)
    s = struct.Struct('! H {}s B {}s B'.format(len(filename),len(mode)) )
    return s.pack(*values)
    
def make_rrq_packet(filename):
    return make_request_packet(tftp.RRQ, filename)

def make_wrq_packet(filename):
    return make_request_packet(tftp.WRQ, filename)


class TftpClient(SocketBase):
    def __init__(self, host='127.0.0.1', port='', filename=None, **argv):
        self.host = host
        self.port = port or default_port()
        self.block_num = 1
        self.is_done = False
        self.status = State.START
        self.action = argv.get('action', 'get')
        self.debug = argv.get('debug', False)
        self.block_size = argv.get('block_size', tftp.DEFAULT_BLOCK_SIZE)
        self.filename = filename
        self.setup_file()
        self.setup_connect()

    @property
    def server_addr(self):
        return (self.host, self.port)

    def setup_file(self):
        if self.filename:
            if self.action == 'get':
                self.fd = open(self.filename, 'wb')
            elif self.action == 'put':
                self.fd = open(self.filename, 'rb')
            else:
                raise Exception('unsupport action %s' % self.action)

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

        opcode = get_opcode(packet)
        if opcode == tftp.ERROR:
            err_code = struct.unpack('!H', packet[2:4])[0]
            err_msg = packet[4:packet_len-1]
            print "Error %s: %s" % (err_code, err_msg)
            sys.exit(err_code)
        elif opcode == tftp.DATA:
            # This is a data packet received from server, save data to file.

            # update port
            if self.port != port:
                self.port = port
            block_num = struct.unpack('!H', packet[2:4])[0]
            if block_num != self.block_num:
                # skip unexpected #block data packet 
                print 'unexpected block num %d' % block_num
                return
            data = packet[4:]
            self.fd.write(data)
            if len(packet) < self.block_size + 2:
                self.is_done = True
                self.fd.close()
                file_len = self.block_size * (self.block_num -1) + len(data)
                print '%d bytes received.' % file_len 
            self.block_num += 1
        elif opcode == tftp.ACK:
            # This is a write request ACK
            # Send next block_size data to server
            if self.port != port:
                self.port = port
            block_num = struct.unpack('!H', packet[2:4])[0]
            self.verbose('received ack for %d' % block_num)
            self.block_num += 1
        else:
            raise Exception('unrecognized packet: %s', str(opcode))
        
    def get_next_packet(self):
        if self.status == State.START:
            opcode = tftp.RRQ if self.action == 'get' else tftp.WRQ
            self.verbose('about to send packet %d' % opcode)
            packet = make_request_packet(opcode, self.filename)
            self.status = State.DATA
        elif self.status == State.DATA:
            if self.action == 'get':
                self.verbose('about to send ack for %d' % (self.block_num - 1))
                packet = make_ack_packet(self.block_num-1)
            elif self.action == 'put':
                self.verbose('about to send data for %d' % (self.block_num - 1))
                data = self.fd.read(self.block_size)
                if len(data) < self.block_size:
                    self.is_done = True
                packet = make_data_packet(self.block_num-1, data)

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
    parser = argparse.ArgumentParser(description='Tftp client in pure python.')
    parser.add_argument('--host', '-s', action='store', dest='host', 
            default='127.0.0.1', help='Server hostname')
    parser.add_argument('--port', '-p', action='store', dest='port', type=int,
            default=69, help='Server port')
    parser.add_argument('--file', '-f', action='store', dest='filename', 
            default='test.txt', help='File to get from server')
    parser.add_argument('--debug', '-d', action='store_true',  
            default=False, help='Debug mode: print more information(debug: False)')
    parser.add_argument('action',  default='get', metavar='action',
            help='Action to conduct: put or get(default: get)')
    args = parser.parse_args()

    tftp_client = TftpClient(args.host, args.port, args.filename,
            action=args.action, debug=args.debug)
    tftp_client.handle()
