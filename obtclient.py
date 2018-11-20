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
import obtmagic
import argparse

class OpenBinTool(object):
    """
    Class DocString
    """
    def __init__(self):
        """
        Method DocString
        """
        # These data should eventually be replaced by a class containing binary data and segments
        self.binary = None
        self.text = None

        # Networking data
        self.socket = None
        self.smartsock = None

        # cli argument parser
        self.parser = None

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
        fd = open(file, 'rb')
        self.binary = fd.read()
        self.text = binary.get_section_by_name('.text').data()
        fd.close()

    def quit(self):
        """
        Method OpenBinTool.quit()
        :return:
        """
        self.smartsock.send("quit")
        data = self.smartsock.recv()
        print(data)
        if data == b"STATUS: OK - Quiting":
            self.smartsock.close()
            print("Quiting OpenBinTool...")
            sys.exit()
        else:
            print("Error: Failure to quit")

    def repl(self):
        """
        Method repl()
        :return:
        """
        # Process user command
        cmd = None
        while True:
            cmd = input("> ")
            if cmd in ["q", "quit"]:
                self.quit()
            elif cmd in ["h", "help"]:
                self.repl_usage()
            elif cmd in ["f", "file"]:
                if self.binary:
                    magic_tool = obtmagic.MagicTool()
                    mt_result = magic_tool.find_magic(self.binary)
                    print(mt_result)
                else:
                    print("Error: no binary loaded")
            elif cmd in ["l", "load"]:
                file = "/bin/ls"  # debugging only
                self.load(file)
            elif cmd in ["d", "disasm"]:
                # Check to see if binary is loaded
                if self.text:
                    self.smartsock.send("disasm")
                    data = self.smartsock.recv()
                    print(data)
                    if data == b"STATUS: OK - Begin":
                        # Binary
                        self.smartsock.send(self.text)
                        data = self.smartsock.recv()
                        print(data.decode('utf-8'))
                else:
                    print("Error: no binary loaded")
            else:
                print("Command {} currently not supported".format(cmd))
                print("Enter (h)elp for a list of commands")

    @staticmethod
    def repl_welcome():
        """
        Method DocString
        :return:
        """
        print("Welcome to the OpenBinTool client!")
        print("Enter \"h\" or \"help\" for a list of commands")

    @staticmethod
    def repl_usage():
        """
        Method DocString
        :return:
        """
        print("Supported Commands:")
        print("\t(l)oad FILE \tLoads the file named FILE")
        print("\t(a)sm FILE  \tAssembles instructions at FILE")
        print("\t(d)isasm    \tDisassembles the currently loaded file")
        print("\t(f)ile      \tIdentify file type of currently loaded file")
        print("\t(q)uit      \tExit program")
        print("\t(h)elp      \tDisplay this message")

    def cli(self):
        """
        Method DocString
        :return:
        """
        self.parser = argparse.ArgumentParser(description="Command Line Interface for OpenBinTools", epilog="Now Hack All The Things!")
        self.parser.add_argument('-f', '--file', action='store_true', help='Identify file type of currently loaded file')
        self.parser.add_argument('-s', '--strings', metavar="TOLERANCE", dest="strtolerance", nargs='?', const=3, default=3, help="Custom strings utility")

        required = self.parser.add_argument_group('required arguments')
        required.add_argument('-l', '--load', metavar="FILE", nargs=1, required=True , help="Specify file to load.")
        args = self.parser.parse_args()


def main():
    """
    Function DocString
    :return:
    """
    # Local variables
    host = 'localhost'  # needs to be in quote
    port = 11337
    tool = OpenBinTool()

    tool.connect(host, port)

    # If no command line arguments are provided enter cli
    if len(sys.argv) == 1:
        # Welcome message
        tool.repl_welcome()

        # REPL menu interface
        tool.repl()

    # Else execute provided arguments and exit
    else:
        tool.cli()


if __name__ == "__main__":
    main()
