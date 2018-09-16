#!/usr/bin/python
# Authors:      Jacob Mills
# Date:         09/09/2018
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
#
#
#
#


from pwn import *
from socket import *
import thread

BUFF = 1024
HOST = '127.0.0.1'
PORT = 11337

class SmartSocket(object):
    def __init__(self,socket):
        self.socket = socket

    def send(self,data):
        self.socket.sendall(struct.pack('!I',len(data)))
        self.socket.sendall(data)

    def recv(self):
        lengthbuf = self.recvall(4)
        length, = struct.unpack('!I', lengthbuf)
        return self.recvall(length)

    def recvall(self,count):
        retval = b''
        while count:
            recbuffer = self.socket.recv(count)
            if not recbuffer:
                return None
            retval += recbuffer
            count -= len(recbuffer)
        return retval

    def close(self):
        self.socket.close()


def handler(client,addr):
    smartsock = SmartSocket(client)
    try:
        data = smartsock.recv()
        if not data:
            raise Exception("No data")
        print "Data received from {}: {}".format(repr(addr),data)

        # Match request
        if data == "asm":
            smartsock.send("STATUS: OK - Begin")
            data = smartsock.recv()
            senddata = asm(data)
            smartsock.send(senddata)
        elif data == "disasm":
            smartsock.send("STATUS: OK - Begin")
            data = smartsock.recv()
            senddata = disasm(data)
            print senddata
            smartsock.send(senddata)
        else:
            smartsock.send("STATUS: ERROR\n")
            smartsock.send(list_commands())
    except Exception as e:
        error = "ERROR: \n\tType: {}\n\tArgs: {}\n\tInfo: {}".format(type(e),e.args,e)
        print error
        smartsock.send(error)

    smartsock.close()
    print "Connection to {} closed".format(repr(addr))

def list_commands():
    return "Supported Commands\n\t1) asm\n\t2) disasm\n"

if __name__=='__main__':
    ADDR = (HOST, PORT)
    serversock = socket(AF_INET, SOCK_STREAM)
    serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serversock.bind(ADDR)
    serversock.listen(5)
    print 'waiting for connection... listening on port', PORT
    while 1:
        client, addr = serversock.accept()
        print "New connection from {}:{}".format(addr[0],addr[1])
        thread.start_new_thread(handler, (client, addr))

