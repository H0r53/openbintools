#!/usr/bin/python3
#
# Authors:      Jacob Mills, Brandon Everhart
# Date:         09/17/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
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


import pwn
import socket
import _thread
import smartsocket

BUFF = 1024
HOST = '127.0.0.1'
PORT = 11337


def handler(client, addr):
    smartsock = smartsocket.SmartSocket(client)
    try:
        data = smartsock.recv()
        if not data:
            raise Exception("No data")
        print("Data received from {}: {}".format(repr(addr), data))

        # Match request
        if data == b"asm":
            smartsock.send("STATUS: OK - Begin")
            data = smartsock.recv()
            senddata = pwn.asm(data)
            smartsock.send(senddata)
        elif data == b"disasm":
            smartsock.send("STATUS: OK - Begin")
            data = smartsock.recv()
            senddata = pwn.disasm(data)
            print(senddata)
            smartsock.send(senddata)
        else:
            smartsock.send("STATUS: ERROR\n")
            smartsock.send(list_commands())
    except Exception as e:
        error = "ERROR: \n\tType: {}\n\tArgs: {}\n\tInfo: {}".format(type(e), e.args, e)
        print(error)
        smartsock.send(error)

    smartsock.close()
    print("Connection to {} closed".format(repr(addr)))

def list_commands():
    return "Supported Commands\n\t1) asm\n\t2) disasm\n"

def main():
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


