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
import SmartSocket
import pwn


def main():
    bin = pwn.ELF('/bin/ls')
    s = socket.socket()
    host = 'localhost'  # needs to be in quote
    port = 11337
    s.connect((host, port))
    smartsock = SmartSocket.SmartSocket(s)
    smartsock.send("disasm")
    data = smartsock.recv()
    print(data)
    if data == b"STATUS: OK - Begin":
        binary = bin.get_section_by_name('.text').data()
        smartsock.send(binary)
        data = smartsock.recv()
        print(data.decode('utf-8'))

    smartsock.close()


if __name__ == "__main__":
    main()
