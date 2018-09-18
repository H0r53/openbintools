#!/usr/bin/python3
#
# Authors:      Jacob Mills, Brandon Everhart
# Date:         09/17/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
#   - Moved to python3#
#   - Formatting according to PyCharm and PEP8
#   - Created SmartSocket.py
#   - Changed types in send from str to bytes (required for py3 ??)
#
#

import struct


class SmartSocket(object):
    def __init__(self, socket):
        self.socket = socket

    def send(self, data):
        self.socket.sendall(struct.pack('!I', len(data)))
        #print(data)
        if isinstance(data, bytes):
            self.socket.sendall(data)
        else:
            self.socket.sendall(bytes(data, 'utf-8'))

    def recv(self):
        lengthbuf = self.recvall(4)
        length, = struct.unpack('!I', lengthbuf)
        return self.recvall(length)

    def recvall(self, count):
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


def main():
    print("SmartSocket.py - main() - Nothing to do")


if __name__ == "__main__":
    main()
