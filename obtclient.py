#!/usr/bin/python3
#
# Authors:      Jacob Mills, Brandon Everhart
# Date:         09/17/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
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


import socket
import smartsocket
import pwn

class OpenBinTool(object):
    def __init__(self):
        self.binary = None
        self.socket = None
        self.smartsock = None

    def connect(self,host,port):
        self.socket = socket.socket()
        self.socket.connect((host, port))
        self.smartsock = smartsocket.SmartSocket(self.socket)



    def welcome(self):
        print("Welcome to the OpenBinTool client!")
        print("Enter \"h\" or \"help\" for a list of commands")

    def usage(self):
        print("Supported Commands:")
        print("\t(l)oad FILE\t\tLoads the file named FILE")
        print("\t(a)sm FILE\t\tAssembles instructions at FILE")
        print("\t(d)isasm\t\tDisassembles the currently loaded file")
        print("\t(q)uit\t\tExit program")
        print("\t(h)elp\t\tDisplay this message")

def main():
    # Local variables
    host = 'localhost'  # needs to be in quote
    port = 11337
    cmd = None
    tool = OpenBinTool()

    # Welcome message
    tool.welcome()

    # Process user command
    while True:
        cmd = input("> ")
        if cmd in ["q","quit"]:
            break
        elif cmd in ["h","help"]:
            tool.usage()
        elif cmd in ["l","load"]:
            bin = pwn.ELF("/bin/ls") # Debug only
            tool.binary = bin.get_section_by_name('.text').data()
        elif cmd in ["d","disasm"]:
            # Check to see if binary is loaded
            if tool.binary:
                tool.connect(host,port)
                tool.smartsock.send("disasm")
                data = tool.smartsock.recv()
                print(data)
                if data == b"STATUS: OK - Begin":
                    # Binary
                    tool.smartsock.send(tool.binary)
                    data = tool.smartsock.recv()
                    print(data.decode('utf-8'))
                tool.smartsock.close()
            else:
                print("Error: no binary loaded")

        else:
            print("Command {} currently not supported".format(cmd))
            print("Enter (h)elp for a list of commands")


if __name__ == "__main__":
    main()
