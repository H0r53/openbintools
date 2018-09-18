#!/usr/bin/python3

"""
# Authors:      Jacob Mills, Brandon Everhart
# Date:         09/18/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
#   - 9/18 Added module, method, and class docstrings
#   - 9/18 Cleaned formatting based on PyCharm, PyLint3, PEP8
#   - 9/18 PyLint score 7.50 --> 10.00/10
#
#   - Moved to python3#
#   - Formatting according to PyCharm and PEP8
#   - Created SmartSocket.py
#   - Changed types in send from str to bytes (required for py3 ??)
#
"""

import struct


class SmartSocket(object):
    """
    Class DocString
    """
    def __init__(self, socket):
        """
        Method DocStrings
        :param socket:
        """
        self.socket = socket

    def send(self, data):
        """
        Method DocString
        :param data:
        :return:
        """
        self.socket.sendall(struct.pack('!I', len(data)))
        #print(data)
        if isinstance(data, bytes):
            self.socket.sendall(data)
        else:
            self.socket.sendall(bytes(data, 'utf-8'))

    def recv(self):
        """
        Method DocString
        :return:
        """
        lengthbuf = self.recvall(4)
        length, = struct.unpack('!I', lengthbuf)
        return self.recvall(length)

    def recvall(self, count):
        """
        Method DocString
        :param count:
        :return:
        """
        retval = b''
        while count:
            recbuffer = self.socket.recv(count)
            if not recbuffer:
                return None
            retval += recbuffer
            count -= len(recbuffer)
        return retval

    def close(self):
        """
        Method DocString
        :return:
        """
        self.socket.close()


def main():
    """
    Function DocString
    :return:
    """
    print("SmartSocket.py - main() - Nothing to do")


if __name__ == "__main__":
    main()
