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
import threading
import os
import random
import signal
import sys

import smartsocket
import obtdisasm
import r2tool
import virustotal_api

BUFF = 1024
HOST = '127.0.0.1'
PORT = 11337


class MyThreads(threading.Thread):
    def __init__(self, client, addr):
        threading.Thread.__init__(self)
        self.kill = False
        self.client = client
        self.addr = addr

    def run(self):
        """
        Function DocString
        :param client:
        :param addr:
        :return:
        """
        smartsock = smartsocket.SmartSocket(self.client)
        disassembler = obtdisasm.ObtDisasm()

        file_mem = None
        file_disk = [None, None]

        try:
            # Diffie Hellman Key Exchange
            aa = int(smartsock.recv())
            bb = (smartsock.shared_base ** smartsock.secret) % smartsock.shared_prime
            smartsock.send(str(bb))
            key = (aa ** smartsock.secret) % smartsock.shared_prime
            smartsock.key = bytes(str(key), 'utf-8')

            while not self.kill:

                data = smartsock.recv()
                if not data:
                    raise Exception("No data")

                print("Data received from {}: {}".format(repr(self.addr), data))

                # Match request
                if data == b"asm":
                    smartsock.send("STATUS: OK - Begin")
                    data = smartsock.recv()
                    senddata = pwn.asm(data)
                    smartsock.send(senddata)
                elif data == b"disasm":
                    smartsock.send("STATUS: OK - Disasm")
                    senddata = disassembler.disasm(file_mem)
                    print(senddata)
                    smartsock.send(senddata)
                elif data == b"load":
                    # Check if a file has been loaded to disk
                    if None in file_disk:
                        # Check if a file has
                        dir = "/tmp/openbintools/"
                        if not os.path.exists(dir):
                            os.makedirs(dir)
                        # Create unique tmp file: /tmp/openbintools/RemoteIP_RemotePORT_FD#_Random#
                        rand = random.SystemRandom().getrandbits(100)
                        file_disk[0] = dir+self.addr[0]+"_"+str(self.addr[1])+"_fd"+str(smartsock.socket.fileno())+"_"+str(rand)
                        file_disk[1] = open(file_disk[0], 'wb+')
                    else:
                        file_disk[1] = open(file_disk[0], 'wb+')
                    smartsock.send("STATUS: OK - Begin")
                    data = smartsock.recv()
                    file_mem = data
                    file_disk[1].write(file_mem)
                elif data == b"radare2":
                    smartsock.send("STATUS: OK - Send cmd")
                    cmd = smartsock.recv()
                    if cmd == b"i":
                        result = r2tool.imports(file_disk[0])
                        smartsock.send(result)
                    elif cmd == b"m":
                        result = r2tool.mainaddr(file_disk[0])
                        smartsock.send(result)
                    elif cmd == b"s":
                        result = r2tool.security(file_disk[0])
                        smartsock.send(result)
                    elif cmd == b"ss":
                        result = r2tool.sections(file_disk[0])
                        smartsock.send(result)
                    elif cmd == b"l":
                        result = r2tool.linkedlibs(file_disk[0])
                        smartsock.send(result)
                    elif cmd == b"f":
                        result = r2tool.functions(file_disk[0])
                        smartsock.send(result)
                    elif cmd == b"p":
                        smartsock.send("STATUS: OK - Send r2pipe cmd")
                        cmd = smartsock.recv()
                        result = r2tool.pipe(str(cmd), file_disk[0])
                        smartsock.send(result)
                    else:
                        smartsock.send("Error: Incorrect arg")
                elif data == b"quit":
                    smartsock.send("STATUS: OK - Quiting")
                    # smartsock.close()
                    # print("Connection to {} closed".format(repr(self.addr)))
                    # try:
                    #     if file_disk[0] is not None:
                    #         file_disk[1].close()
                    #         os.remove(file_disk[0])
                    # except:
                    #     print("Error: Problem closing/removing tmp file")
                    break
                elif data == b"virus":
                    if None not in file_disk:
                        smartsock.send("STATUS: OK - Virus Check")
                        response = virustotal_api.queue(file_disk[0])
                        if "Error: Missing VirusTotal API Key" not in response:
                            response_pretty = ""
                            for key, value in response.items():
                                response_pretty = response_pretty + str(key) + ": " + str(value) + "\n"
                            smartsock.send(response_pretty)
                            result = virustotal_api.reports(response['resource'])
                            smartsock.send(result)
                        else:
                            smartsock.send(response)  # send response error
                            smartsock.send(response)  # send response error, as it is the same error for report
                    else:
                        smartsock.send("Error: No file loaded")
                else:
                    smartsock.send("STATUS: ERROR\n")
        except KeyboardInterrupt:
            pass
        except Exception as exp:
            # Exception is to broad
            error = "ERROR: \n\tType: {}\n\tArgs: {}\n\tInfo: {}".format(type(exp), exp.args, exp)
            print(error)
            smartsock.send(error)

        smartsock.close()
        print("Connection to {} closed".format(repr(self.addr)))
        try:
            if file_disk[0] is not None:
                file_disk[1].close()
                os.remove(file_disk[0])
        except:
            print("Error: Problem closing/removing tmp file")


def alive(threads):
    for thread in threads:
        if thread.isAlive():
            return True
    return False


def main():
    """
    Function DocString
    :return:
    """
    print('Press Ctrl+C to exit')

    addr = (HOST, PORT)
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversock.bind(addr)
    serversock.listen(5)
    threads = []
    print('waiting for connection... listening on port', PORT)
    while 1:
        try:
            client, addr = serversock.accept()
            print("New connection from {}:{}".format(addr[0], addr[1]))
            thread = MyThreads(client, addr)
            thread.start()
            threads.append(thread)

        except KeyboardInterrupt:
            for thread in threads:
                if thread is not None and thread.isAlive():
                    thread.join(1)

            print("Sending kill to threads...")
            for thread in threads:
                thread.kill = True

            break

    print("Exiting...")


if __name__ == '__main__':
    main()
