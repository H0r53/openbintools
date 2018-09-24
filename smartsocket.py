#!/usr/bin/python3

"""
# Authors:      Jacob Mills, Brandon Everhart
# Date:         09/22/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
#   - 9/22 Added crypto
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
import random
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
        self.blocksize = Blowfish.block_size    # Default Blowfish blocksize
        self.sharedPrime = 23
        self.sharedBase = 5
        self.secret = random.SystemRandom().getrandbits(20)
        self.key = b'arbitrarily long key'      # Need to implement key exchange
        self.mode = Blowfish.MODE_CBC           # Do we want CBC??

    def send(self, data):  # , encrypt=False): used if toggling crypto
        """
        Method SmartSocket.send()

        A '1' or '0' is appended to the beginning of the msg to represent if
        encryption/decryption is needed, this means when receiving data we
        must check and remove the first byte.

        However, when sending the length of the buffer the extra byte is not sent
            so the getlen flag is added to the recv and recvall method

        :param data:
        :param encrypt:
        :return:
        """
        if not isinstance(data, bytes):
            data = bytes(data, 'utf-8')

        # Used if toggling crypto
        # if encrypt:
        #     data = b'1' + self.encrypt(data)
        # else:
        #     data = b'0' + data

        ciphertext = self.encrypt(data)
        self.socket.sendall(struct.pack('!I', len(ciphertext)))
        self.socket.sendall(ciphertext)

    def recv(self):
        """
        Method SmartSock.recv()

        A '1' or '0' is appended to the beginning of the msg to represent if
        encryption/decryption is needed, this means when receiving data we
        must check and remove the first byte.

        However, when sending the length of the buffer the extra byte is not sent
            so the getlen flag is added to the recv and recvall method

        :return:
        """
        lengthbuf = self.recvall(4)  # , getlen=True) Used if toggling crypto
        length, = struct.unpack('!I', lengthbuf)
        ciphertext = self.recvall(length)
        return self.decrypt(ciphertext)

    def recvall(self, count):  # , getlen=False): Used if toggling crypto
        """
        Method SmartSock.recvall()
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

        # Used if toggling crypto
        # if getlen:
        #     return retval  # no extra byte was sent
        # elif retval[0] == 49:  # encrypt == True == 1 --> ord(1) == 49
        #     return self.decrypt(retval[1:])
        # return retval[1:]  # encryption isn't being used

        return retval

    def encrypt(self, plaintext):
        """
        Method SmartSocket.encrypt()
        :param plaintext:
        :return:
        """
        nonce = Random.new().read(self.blocksize)
        cipher = Blowfish.new(self.key, self.mode, nonce)
        padding = self.pad(plaintext)
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
        padded_msg = cipher.decrypt(ciphertext)
        msg = self.unpad(padded_msg)
        return msg

    def pad(self, plaintext):
        """
        Method SmartSocket.pad()

        msg is padded with the repeated bytes of the pad length.
        The last byte encodes how many bytes of padding to remove

        Example:
            if blocksize = 20 and len(msg) = 14
                then pad_length = 6
            then
                padding = \x06\x06\x06\x06\x06\x06\
            and
                msg = msg + padding\

        :param plaintext:
        :return:
        """
        pad_length = self.blocksize - (len(plaintext) % self.blocksize)
        padding = [pad_length] * pad_length
        return struct.pack('b' * pad_length, *padding)

    @staticmethod
    def unpad(msg):
        """
        Method SmartSocket.unpad()

        The last byte encodes how many bytes of padding to remove

        :param msg:
        :return:
        """
        if isinstance(msg[-1], int):
            pad_length = msg[-1]
        else:
            pad_length = ord(msg[-1])
        return msg[:-pad_length]

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
