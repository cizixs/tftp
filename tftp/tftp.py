#!/bin/env python

"""Tftp common utility module.

This module defines constant and utility functions
for tftp client and tftp server.
"""
import socket
import struct

# Protocol type
RRQ, WRQ, DATA, ACK, ERROR, OACK = range(1,7)
DEFAULT_BLOCK_SIZE = 512
MAX_BLOCK_SIZE = 1428

def default_port(): 
    return socket.getservbyname('tftp', 'udp')

def make_data_packet(block_num, data):
    return struct.pack('! H H', DATA, block_num) + data

def make_ack_packet(block_num):
    return struct.pack('!H H', ACK, block_num)

def get_opcode(packet):
    return struct.unpack('!H', packet[:2])[0]

def get_blocknum(packet):
    return struct.unpack('!H', packet[2:4])[0]

class SocketBase(object):

    @property
    def max_packet_size(self):
        return self.block_size + 4

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

    def verbose(self, msg):
        if self.debug:
        	print(msg)
