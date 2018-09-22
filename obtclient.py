#!/usr/bin/python3

"""
# Authors:      Jacob Mills, Brandon Everhart
# Date:         09/17/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
#   - 9/22 Added DH key Exchange
#
#   - 9/20 Fixed display issues with help command
#   - 9/19 OpenBinTool cli, load, and quit methods
#
#   - 9/18 Added module, method, and class docstrings
#   - 9/18 Cleaned formatting based on PyCharm, PyLint3, PEP8
#   - 9/18 PyLint score 6.79 --> 10.00/10
#
#   - Moved to python3
#   - from pwn import * --> import pwn (best practice)
#   - Cleaned formatting according to PyCharm and PEP8
#   - Added if __name__ == "__main__"
#   - def main()
#   - Moved SmartSocket class to SmartSocket.py
#   - Removed import struct
#   - Changed types from str to bytes for SmartSocket (required for py3 ??)
#
#
"""

import sys
import socket
import pwn
import smartsocket


class OpenBinTool(object):
    """
    Class DocString
    """
    def __init__(self):
        """
        Method DocString
        """
        self.binary = None
        self.socket = None
        self.smartsock = None
        # self.encrypt = False Used if toggling crypto

    def connect(self, host, port):
        """
        Method DocString
        :param host:
        :param port:
        :return:
        """
        self.socket = socket.socket()
        self.socket.connect((host, port))
        self.smartsock = smartsocket.SmartSocket(self.socket)
        self.smartsock.key = self.keyexchange()

    def keyexchange(self):
        """
        Method OpenBinTool.keyexchange()
        Diffie Hellman key exchange
        :return:
        """
        aa = (self.smartsock.sharedBase**self.smartsock.secret) % self.smartsock.sharedPrime
        self.smartsock.send(str(aa))
        bb = int(self.smartsock.recv())
        key = (bb**self.smartsock.secret) % self.smartsock.sharedPrime
        key = bytes(str(key), 'utf-8')
        return key

    def load(self, file):
        """
        Method OpenBinTool.load()
        :param file:
        :return:
        """
        binary = pwn.ELF(file)
        self.binary = binary.get_section_by_name('.text').data()

    def quit(self):
        """
        Method OpenBinTool.quit()
        :return:
        """
        if self.smartsock:
            self.smartsock.close()
        print("Quiting OpenBinTool...")
        sys.exit()

    def cli(self, host, port):
        """
        Method cli()
        :param host:
        :param port:
        :return:
        """
        # Process user command
        cmd = None
        while True:
            cmd = input("> ")
            if cmd in ["q", "quit"]:
                self.quit()
            elif cmd in ["h", "help"]:
                self.usage()
            elif cmd in ["l", "load"]:
                file = "/bin/ls"  # debugging only
                self.load(file)
            # Used if toggling crypto
            # elif cmd in ["e", "encrypt"]:
            #     self.connect(host, port)
            #     self.encrypt = not self.encrypt
            #     self.smartsock.send("encrypt", self.encrypt)
            #     data = self.smartsock.recv()
            #     print(data)
            #     print("Encrypt =", self.encrypt)
            elif cmd in ["d", "disasm"]:
                # Check to see if binary is loaded
                if self.binary:
                    self.connect(host, port)
                    self.smartsock.send("disasm")  # , self.encrypt) Used if toggling crypto
                    data = self.smartsock.recv()
                    print(data)
                    if data == b"STATUS: OK - Begin":
                        # Binary
                        self.smartsock.send(self.binary)  # , self.encrypt) Used if toggling crypto
                        data = self.smartsock.recv()
                        print(data.decode('utf-8'))
                    self.smartsock.close()
                else:
                    print("Error: no binary loaded")
            else:
                print("Command {} currently not supported".format(cmd))
                print("Enter (h)elp for a list of commands")

    @staticmethod
    def welcome():
        """
        Method DocString
        :return:
        """
        print("Welcome to the OpenBinTool client!")
        print("Enter \"h\" or \"help\" for a list of commands")

    @staticmethod
    def usage():
        """
        Method DocString
        :return:
        """
        print("Supported Commands:")
        print("\t(l)oad FILE \tLoads the file named FILE")
        # print("\t(e)ncrypt   \tToggle encryption of communication") Used if toggling crypto
        print("\t(a)sm FILE  \tAssembles instructions at FILE")
        print("\t(d)isasm    \tDisassembles the currently loaded file")
        print("\t(q)uit      \tExit program")
        print("\t(h)elp      \tDisplay this message")


def main():
    """
    Function DocString
    :return:
    """
    # Local variables
    host = 'localhost'  # needs to be in quote
    port = 11337
    tool = OpenBinTool()

    # Welcome message
    tool.welcome()

    # Command Line Interface
    tool.cli(host, port)


if __name__ == "__main__":
    main()
