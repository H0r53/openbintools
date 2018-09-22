#!/usr/bin/python3

"""
# Authors:      Jacob Mills, Brandon Everhart
# Date:         09/20/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
#   - 9/20 Added crypto
#
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
from Crypto.Cipher import Blowfish
from Crypto import Random


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
        self.blocksize = Blowfish.block_size
        self.key = b'arbitrarily long key'
        self.mode = Blowfish.MODE_CBC

    def send(self, data, encrypt=False):
        """
        Method SmartSocket.send()
        :param data:
        :param encrypt:
        :return:
        """
        if not isinstance(data, bytes):
            data = bytes(data, 'utf-8')
        if encrypt:
            data = b'1' + self.encrypt(data)
        else:
            data = b'0' + data
        self.socket.sendall(struct.pack('!I', len(data)))
        self.socket.sendall(data)

    def recv(self):
        """
        Method DocString
        :return:
        """
        lengthbuf = self.recvall(4, getlen=True)
        length, = struct.unpack('!I', lengthbuf)
        return self.recvall(length)

    def recvall(self, count, getlen=False):
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
        if getlen:
            return retval
        elif retval[0] == 49:
            return self.decrypt(retval[1:])
        return retval[1:]

    def encrypt(self, plaintext):
        """
        Method SmartSocket.encrypt()
        :param plaintext:
        :return:
        """
        nonce = Random.new().read(self.blocksize)
        cipher = Blowfish.new(self.key, self.mode, nonce)
        length = self.blocksize - divmod(len(plaintext), self.blocksize)[1]
        padding = [length]*length
        padding = struct.pack('b'*length, *padding)
        msg = nonce + cipher.encrypt(plaintext + padding)
        return msg

    def decrypt(self, ciphertext):
        """
        Method SmartSocket.decrypt()
        :param ciphertext:
        :return:
        """
        nonce = ciphertext[:self.blocksize]
        ciphertext = ciphertext[self.blocksize:]
        cipher = Blowfish.new(self.key, self.mode, nonce)
        msg = cipher.decrypt(ciphertext)
        last_byte = msg[-1]
        msg = msg[:- (last_byte if isinstance(last_byte, int) else ord(last_byte))]
        return msg

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
