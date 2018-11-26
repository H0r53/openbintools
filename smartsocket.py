#!/usr/bin/python3

"""
    File:
        - smartsocket.py

    Authors:
        - Jacob Mills,
        - Brandon Everhart,
        - Taylor Shields

    Date: 11/25/2018

    Description:
        - A network-based x86_64 (dis)/assembler API for Python.

    Changelog:
        - 9/18 Created SmartSocket
        - 9/18 Added module, method, and class docstrings
        - 9/18 Moved to python3
        - 9/18 Changed types in send from str to bytes (required for py3 ??)
        - 9/18 Cleaned formatting based on PyCharm, PyLint3, PEP8
        - 9/18 Pylint score 7.50 --> 10.00/10
        - 9/22 Added crypto functionality
        - 11/25 Documented
        - 11/25 Cleaned formatting based on PyCharm, PyLint3, PEP8
        - 11/25 Pylint score 8.71/10 --> 10.00/10
"""

import struct
import random
from Crypto.Cipher import Blowfish
from Crypto import Random


def docs():
    """
    Function:
        smartsocket.docs()

        Description:
            Prints all docstrings related to this file.

        Parameters:
            - None

        Return:
            - None
    """
    print(__doc__)
    print(docs.__doc__)
    print(SmartSocket.__init__.__doc__)
    print(SmartSocket.send.__doc__)
    print(SmartSocket.recv.__doc__)
    print(SmartSocket.recvall.__doc__)
    print(SmartSocket.encrypt.__doc__)
    print(SmartSocket.decrypt.__doc__)
    print(SmartSocket.pad.__doc__)
    print(SmartSocket.unpad.__doc__)
    print(SmartSocket.close.__doc__)


class SmartSocket():
    """
    Class:
        smartsocket.SmartSocket

        Description:
            -

        Parameters:
            - None

        Functions:
            - __init__()
            - send()
            - recv()
            - recvall()
            - encrypt()
            - decrypt()
            - pad()
            - unpad()
            - close()
    """
    def __init__(self, socket):
        """
        Function:
            smartsocket.SmartSocket.__init__()

        Description:
            -

        Parameters:
            - socket:
                Description - ,
                Data Type - socket,
                Requirement - mandatory,
                Argument Type - Positional (1st)

        Return:
            - None
        """
        self.socket = socket
        self.blocksize = Blowfish.block_size    # Default Blowfish blocksize
        self.shared_prime = 23
        self.shared_base = 5
        self.secret = random.SystemRandom().getrandbits(20)
        self.key = b'arbitrarily long key'
        self.mode = Blowfish.MODE_CBC           # Do we want CBC??

    def send(self, data):
        """
        Function:
            smartsocket.SmartSocket.send()

        Description:
            - A '1' or '0' is appended to the beginning of the msg to represent if
            encryption/decryption is needed; this means when receiving data we
            must check and remove the first byte.
            - However, when sending the length of the buffer, the extra byte is not sent
            so the getlen flag is added to the recv and recvall method.

        Parameters:
            - data:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)

        Return:
            - None
        """
        if not isinstance(data, bytes):
            data = bytes(data, 'utf-8')
        ciphertext = self.encrypt(data)
        self.socket.sendall(struct.pack('!I', len(ciphertext)))
        self.socket.sendall(ciphertext)

    def recv(self):
        """
        Function:
            smartsocket.SmartSocket.recv()

        Description:
            - A '1' or '0' is appended to the beginning of the msg to represent if
            encryption/decryption is needed, this means when receiving data we
            must check and remove the first byte.
            - However, when sending the length of the buffer the extra byte is not sent
            so the getlen flag is added to the recv and recvall method.

        Parameters:
            - None

        Return:
            - self.decrypt(ciphertext):
                Description -
                Data Type -
        """
        lengthbuf = self.recvall(4)
        length, = struct.unpack('!I', lengthbuf)
        ciphertext = self.recvall(length)
        return self.decrypt(ciphertext)

    def recvall(self, count):
        """
        Function:
            smartsocket.SmartSocket.recvall()

        Description:
            -

        Parameters:
            - count:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)

        Return:
            - retval:
                Description -
                Data Type -
        """
        retval = b''
        while count:
            recbuffer = self.socket.recv(count)
            if not recbuffer:
                return None
            retval += recbuffer
            count -= len(recbuffer)
        return retval

    def encrypt(self, plaintext):
        """
        Function:
            smartsocket.SmartSocket.encrypt()

        Description:
            -

        Parameters:
            - plaintext:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)

        Return:
            - msg:
                Description -
                Data Type -
        """
        nonce = Random.new().read(self.blocksize)
        cipher = Blowfish.new(self.key, self.mode, nonce)
        padding = self.pad(plaintext)
        msg = nonce + cipher.encrypt(plaintext + padding)
        return msg

    def decrypt(self, ciphertext):
        """
        Function:
            smartsocket.SmartSocket.decrypt()

        Description:
            -

        Parameters:
            - ciphertext:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)

        Return:
            - msg:
                Description -
                Data Type -
        """
        nonce = ciphertext[:self.blocksize]
        ciphertext = ciphertext[self.blocksize:]
        cipher = Blowfish.new(self.key, self.mode, nonce)
        padded_msg = cipher.decrypt(ciphertext)
        msg = self.unpad(padded_msg)
        return msg

    def pad(self, plaintext):
        """
        Function:
            smartsocket.SmartSocket.pad()

        Description:
            - msg is padded with the repeated bytes of the pad length.
            - The last byte encodes how many bytes of padding to remove.
            - Example:
                if blocksize = 20 and len(msg) = 14
                    then pad_length = 6
                then
                    padding = \x06\x06\x06\x06\x06\x06\
                and
                    msg = msg + padding\

        Parameters:
            - plaintext:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)

        Return:
            - struct.pack('b' * pad_length, *padding):
                Description -
                Data Type -
        """
        pad_length = self.blocksize - (len(plaintext) % self.blocksize)
        padding = [pad_length] * pad_length
        return struct.pack('b' * pad_length, *padding)

    @staticmethod
    def unpad(msg):
        """
        Function:
            smartsocket.SmartSocket.unpad()

        Description:
            -  The last byte encodes how many bytes of padding to remove.

        Parameters:
            - msg:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)

        Return:
            - msg[:-pad_length]
                Description -
                Data Type -
        """
        if isinstance(msg[-1], int):
            pad_length = msg[-1]
        else:
            pad_length = ord(msg[-1])
        return msg[:-pad_length]

    def close(self):
        """
        Function:
            smartsocket.SmartSocket.close()

        Description:
            -

        Parameters:
            - None

        Return:
            - None
        """
        self.socket.close()


if __name__ == "__main__":
    docs()
