#!/usr/bin/python
#
#
#

import socket
import struct
from pwn import *

class SmartSocket(object):
    def __init__(self,socket):
        self.socket = socket

    def send(self,data):
        self.socket.sendall(struct.pack('!I',len(data)))
        print data
        self.socket.sendall(data)

    def recv(self):
        lengthbuf = self.recvall(4)
        length, = struct.unpack('!I', lengthbuf)
        return self.recvall(length)

    def recvall(self,count):
        retval = b''
        while count:
            recbuffer = self.socket.recv(count)
            if not recbuffer:
                return None
            retval += recbuffer
            count -= len(recbuffer)
        return retval

    def close(self):
        self.socket.close()


bin = ELF('/bin/ls')
s = socket.socket()
host = 'localhost' # needs to be in quote
port = 11337
s.connect((host, port))
smartsock = SmartSocket(s)
smartsock.send("disasm")
data = smartsock.recv()
print data
if data == "STATUS: OK - Begin":
    binary=bin.get_section_by_name('.text').data()
    smartsock.send(binary)
    data = smartsock.recv()
    print data

smartsock.close()
