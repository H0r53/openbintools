#!/usr/bin/python3

"""
# Authors:      Jacob Mills, Brandon Everhart
# Date:         11/22/2018
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

# Standard Module Imports
import sys
import socket
import argparse
import signal

# Project File Imports
import magictool
import smartsocket
import stringtool
import loadertool


class OpenBinTool:
    """
    Class DocString
    """
    def __init__(self):
        """
        Method DocString
        """
        # These data should eventually be replaced by a class containing binary data and segments
        self.binary = None
        self.binary_path = None
        self.text = None

        # Networking data
        self.socket = None
        self.smartsock = None

        # cli argument parser
        self.parser = None

    def asm(self):
        """

        :return:
        """
        self.smartsock.send("asm")
        data = self.smartsock.recv()
        if data == b"STATUS: OK - Asm":
            data = self.smartsock.recv()
            print("\nASM:\n"+"-"*50+"\n"+data.decode('utf-8'))
        else:
            print("\nASM:\n"+"-"*50+"\nError: Possibly no binary loaded")

    def connect(self, host, port):
        """
        Method DocString
        :param host:
        :param port:
        :return:
        """
        try:
            self.socket = socket.socket()
            self.socket.connect((host, port))
            self.smartsock = smartsocket.SmartSocket(self.socket)
            self.smartsock.key = self.keyexchange()
        except ConnectionRefusedError:
            print("NOTE: Connection to server at {}:{} failed.\nOnly local client features will be functional\n".format(
                host,
                port)
            )

    def cli(self):
        """
        Method DocString
        :return:
        """
        self.parser = argparse.ArgumentParser(
            description="Command Line Interface for OpenBinTools",
            epilog="Now Hack All The Things!"
        )
        self.parser.add_argument(
            '-a',
            '--asm',
            action='store_true',
            help="Return assemble of the loaded file"
        )
        self.parser.add_argument(
            '-d',
            '--disasm',
            action='store_true',
            help="Display disassemble of the loaded file"
        )
        self.parser.add_argument(
            '-f',
            '--file',
            action='store_true',
            help='Identify file type of currently loaded file'
        )
        self.parser.add_argument(
            '-i',
            '--info',
            action='store_true',
            help="Print parsed binary info"
        )
        self.parser.add_argument(
            '-r',
            '--radare2',
            nargs="+"
        )
        self.parser.add_argument(
            '-s',
            '--strings',
            metavar="TOLERANCE",
            dest="strtolerance",
            nargs='?',
            const=3,
            default=None,
            help="Strings utility"
        )
        self.parser.add_argument(
            '-v',
            '--virus',
            action='store_true',
            help="Check the loaded binary against VirusTotal"
        )
        required = self.parser.add_argument_group('required arguments')
        required.add_argument(
            '-l',
            '--load',
            metavar="FILE",
            nargs=1,
            required=True,
            help="Specify file to load."
        )
        args = self.parser.parse_args()

        try:
            # Load file is mandatory so no need for "if" statement
            self.load(["-l", args.load[0]])
            if args.file:
                self.file()
            if args.info:
                self.info()
            if args.strtolerance:
                self.strings(["-s", args.strtolerance])
            if self.smartsock:
                if args.asm:
                    self.asm()
                if args.disasm:
                    self.disasm()
                if args.virus:
                    self.virus()
                if args.radare2:
                    # choices=["f", "i", "l", "m", "p", "s", "ss"]
                    if args.radare2[0] in ["f", "i", "l", "m", "s", "ss"]:
                        self.r2(["-r", args.radare2[0]])
                    elif args.radare2[0] == 'p':
                        self.r2(["-r", args.radare2[0], args.radare2[1]])
            self.quit()
        except (BrokenPipeError, IOError):
            self.quit(silent=True)

    def disasm(self):
        """

        :return:
        """
        self.smartsock.send("disasm")
        data = self.smartsock.recv()
        if data == b"STATUS: OK - Disasm":
            data = self.smartsock.recv()
            print("\nDISASM:\n"+"-"*50+"\n"+data.decode('utf-8'))
        else:
            print("\nDISASM:\n"+"-"*50+"\nError: Possibly no binary loaded")

    def file(self):
        """

        :return:
        """
        if self.binary:
            magic_tool = magictool.MagicTool()
            mt_result = magic_tool.find_magic(self.binary)
            print("\nFILE:\n"+"-"*50+"\n"+mt_result)
        else:
            print("\nFILE:\n"+"-"*50+"\nError: Possibly no binary loaded")

    def info(self):
        """

        :return:
        """
        if self.binary_path:
            print("\nINFO:\n"+"-"*50)
            obj = loadertool.LoaderTool(self.binary_path)
            if obj.ELF:
                info = obj.ELF.info()
            elif obj.PE:
                info = obj.PE.info()

            print(info)
        else:
            print("\nINFO:\n"+"-"*50+"\nError: Possibly no binary loaded")

    def keyexchange(self):
        """
        Method OpenBinTool.keyexchange()
        Diffie Hellman key exchange
        :return:
        """
        aa = (self.smartsock.shared_base**self.smartsock.secret) % self.smartsock.shared_prime
        self.smartsock.send(str(aa))
        bb = int(self.smartsock.recv())
        key = (bb**self.smartsock.secret) % self.smartsock.shared_prime
        key = bytes(str(key), 'utf-8')
        return key

    def load(self, cmd):
        """
        Method OpenBinTool.load()
        :param cmd:
        :return:
        """
        if len(cmd) == 2:
            self.binary_path = cmd[1]
            print("\nLOAD:\n" + "-" * 50)
            try:
                fd = open(self.binary_path, 'rb')
                self.binary = fd.read()
                print("LOCAL SUCCESS")
                if self.smartsock:
                    self.smartsock.send("load")
                    data = self.smartsock.recv()
                    if data == b"STATUS: OK - Begin":
                        self.smartsock.send(self.binary)
                        fd.close()
                        print("REMOTE SUCCESS")
                    else:
                        print("REMOTE Error: Failure to load file")
            except FileNotFoundError:
                print("LOCAL Error: File does not exists")
                self.binary = None
                self.binary_path = None
        else:
            print("\nLOAD:\n"+"-"*50+"\nError: Missing FILE to load")

    def quit(self, silent=False):
        """
        Method OpenBinTool.quit()
        :return:
        """
        if self.smartsock:
            self.smartsock.send("quit")
            data = self.smartsock.recv()
            if data == b"STATUS: OK - Quiting":
                self.smartsock.close()
                if not silent:
                    print("\nQUIT:\n"+"-"*50+"\nSuccess")
                sys.exit()
            else:
                if not silent:
                    print("\nQUIT:\n"+"-"*50+"\nError: Failure to quit")
        else:
            print("\nQUIT:\n" + "-" * 50 + "\nSuccess")
            sys.exit()

    def r2(self, cmd):
        """

        :param cmd:
        :return:
        """
        if len(cmd) >= 2:
            options = cmd[1:]
            self.smartsock.send("radare2")
            data = self.smartsock.recv()
            if data == b"STATUS: OK - Send cmd":
                self.smartsock.send(options[0])
                result = self.smartsock.recv()
                if result == b"STATUS: OK - Send r2pipe cmd":
                    self.smartsock.send(options[1])
                    result = self.smartsock.recv()
                print("\nR2:\n"+"-"*50+"\n"+result.decode("utf-8"))
            else:
                print("\nR2:\n"+"-"*50+"\nError: Possibly no binary loaded")
        else:
            print("\nR2:\n"+"-"*50+"\nError: Must supply option when using radare2 flag")

    def repl(self):
        """
        Method repl()
        :return:
        """
        # Process user command
        cmd = None
        while True:
            cmd = input("> ").split()
            if cmd:
                if cmd[0] in ["f", "file"]:
                    self.file()
                elif cmd[0] in ["h", "help"]:
                    self.repl_usage()
                elif cmd[0] in ["i", "info"]:
                    self.info()
                elif cmd[0] in ["l", "load"]:
                    self.load(cmd)
                elif cmd[0] in ["s", "strings"]:
                    self.strings(cmd)
                elif cmd[0] in ["q", "quit"]:
                    self.quit()
                elif self.smartsock:
                    if cmd[0] in ["a", "asm"]:
                        self.asm()
                    elif cmd[0] in ["d", "disasm"]:
                        self.disasm()
                    elif cmd[0] in ["r", "radare2"]:
                        self.r2(cmd)
                    elif cmd[0] in ["v", "virus"]:
                        self.virus()
                    else:
                        print("Command {} currently not supported".format(cmd))
                        print("Enter (h)elp for a list of commands")
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
        print("\t(a)sm FILE  \tAssembles instructions at FILE")
        print("\t(d)isasm    \tDisassembles the currently loaded file")
        print("\t(f)ile      \tIdentify file type of currently loaded file")
        print("\t(h)elp      \tDisplay this message")
        print("\t(i)nfo      \tPrint parsed binary info")
        print("\t(l)oad FILE \tLoads the file named FILE")
        print("\t(r)adare2 OPT\tInteract with radare2 using option OPT")
        print("\t(s)trings TOL\tDisplays ASCII printable strings with tolerance TOL")
        print("\t(q)uit      \tExit program")
        print("\t(v)irus     \tCheck the loaded file against VirusTotal")

    def strings(self, cmd):
        """

        :param cmd:
        :return:
        """
        if self.binary:
            if len(cmd) == 2:
                print("\nSTRINGS:\n"+"-"*50)
                strlist = stringtool.strings(self.binary, int(cmd[1]))
            else:
                print("\nSTRINGS:\n" + "-" * 50)
                strlist = stringtool.strings(self.binary)

            for key, value in strlist.items():
                print("[{}] {}".format(value, key))
        else:
            print("\nSTRINGS:\n"+"-"*50+"\nError: No binary loaded")

    def virus(self):
        """

        :return:
        """
        self.smartsock.send("virus")
        data = self.smartsock.recv()
        if data == b"STATUS: OK - Virus Check":
            print("\nVIRUS:\n" + "-" * 50)
            response = self.smartsock.recv().decode('utf-8').strip()
            print("RESPONSE:\n"+response)
            data = self.smartsock.recv().decode('utf-8').strip()
            print("\nREPORT:\n" + data)
        else:
            print("\nVIRUS:\n"+"-"*50+"\nError: Possibly no binary loaded")


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

    try:
        # If no command line arguments are provided enter cli
        if len(sys.argv) == 1:
            # Welcome message
            tool.repl_welcome()

            # REPL menu interface
            try:
                tool.repl()
            except BrokenPipeError:
                print("ERROR: Connection to server lost.\nSwitching to LOCAL")
                tool.smartsock = None
                tool.repl()
        # Else execute provided arguments and exit
        else:
            tool.cli()
    except (KeyboardInterrupt, EOFError):
        tool.quit()
    except BrokenPipeError:
        print("ERROR: Connection to server lost")
        sys.exit()


if __name__ == "__main__":
    main()
