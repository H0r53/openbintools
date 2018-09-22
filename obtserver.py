#!/usr/bin/python3

"""
# Authors:      Jacob Mills, Brandon Everhart
# Date:         09/17/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
#   - 9/22 Added DH key Exchange
#   - 9/22 Encryt command now toggles encryption on the server as well
#   - 9/22 Global Encrypt is bad practice
#   - 9/22 Pylint score 9.79 --> 9.64/10
#
#   - 9/18 Added module, method, and class docstrings
#   - 9/18 Cleaned formatting based on PyCharm, PyLint3, PEP8
#   - 9/18 PyLint score 8.33 --> 9.79/10
#
#   - Moved to python3
#   - import thread --> import _thread (name changed in py3)
#   - from pwn import * --> import pwn (best practice)
#   - from socket import * --> import socket (best practice)
#   - Cleaned formatting according to PyCharm and PEP8
#   - def main()
#   - Moved SmartSocket class to SmartSocket.py
#   - Changed types from str to bytes for SmartSocket (required for py3 ??)
#
#
"""


import socket
import pwn
import _thread
import smartsocket
import obtdisasm

BUFF = 1024
HOST = '127.0.0.1'
PORT = 11337

# ENCRYPT = False Used if toggling crypto


def handler(client, addr):
    """
    Function DocString
    :param client:
    :param addr:
    :return:
    """
    # global ENCRYPT Used if toggling crypto
    smartsock = smartsocket.SmartSocket(client)
    disassembler = obtdisasm.ObtDisasm()
    try:
        # Diffie Hellman Key Exchange
        aa = int(smartsock.recv())
        bb = (smartsock.sharedBase ** smartsock.secret) % smartsock.sharedPrime
        smartsock.send(str(bb))
        key = (aa ** smartsock.secret) % smartsock.sharedPrime
        smartsock.key = bytes(str(key), 'utf-8')

        data = smartsock.recv()
        if not data:
            raise Exception("No data")
        print("Data received from {}: {}".format(repr(addr), data))

        # Match request
        if data == b"asm":
            smartsock.send("STATUS: OK - Begin")  # , ENCRYPT) Used if toggling crypto
            data = smartsock.recv()
            senddata = pwn.asm(data)
            smartsock.send(senddata)  # , ENCRYPT) Used if toggling crypto
        elif data == b"disasm":
            smartsock.send("STATUS: OK - Begin")  # , ENCRYPT) Used if toggling crypto
            data = smartsock.recv()
            senddata = disassembler.disasm(data)
            print(senddata)
            smartsock.send(senddata)  # , ENCRYPT) Used if toggling crypto
        # Used if toggling crypto
        # elif data == b"encrypt":
        #     ENCRYPT = not ENCRYPT
        #     smartsock.send("STATUS: OK - Begin", ENCRYPT)
        else:
            smartsock.send("STATUS: ERROR\n")
            smartsock.send(list_commands())

    except Exception as exp:
        # Exception is to broad
        error = "ERROR: \n\tType: {}\n\tArgs: {}\n\tInfo: {}".format(type(exp), exp.args, exp)
        print(error)
        smartsock.send(error)

    smartsock.close()
    print("Connection to {} closed".format(repr(addr)))


def list_commands():
    """
    Function DocString
    :return:
    """
    return "Supported Commands\n\t1) asm\n\t2) disasm\n"


def main():
    """
    Function DocString
    :return:
    """
    addr = (HOST, PORT)
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversock.bind(addr)
    serversock.listen(5)
    print('waiting for connection... listening on port', PORT)
    while 1:
        client, addr = serversock.accept()
        print("New connection from {}:{}".format(addr[0], addr[1]))
        _thread.start_new_thread(handler, (client, addr))


if __name__ == '__main__':
    main()
