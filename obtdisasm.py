#!/usr/bin/python3

"""
# Authors:      Brandon Everhart
# Date:         09/21/2018
#
# Description:  A network-based x86_64 (dis)/assembler API for Python
#
# Changelog:
#   - 9/20 File created
#
#
"""

import pwn


class ObtDisasm(object):
    """
    Class DocString
    """
    def __init__(self, arch='amd64', bits=64, endian='little'):
        """
        Method DocString
        """
        self.arch = arch
        self.bits = bits
        self.endian = endian

    @staticmethod
    def disasm(data):
        """
        Method ObtDisasm.disasm()
        :param data:
        :return:
        """
        return pwn.disasm(data)

    def update(self, arch='amd64', bits=64, endian='little'):
        """
        Method ObtDisasm.update()
        :param arch:
        :param os:
        :param bits:
        :param endian:
        :return:
        """
        self.arch = arch
        self.bits = bits
        self.endian = endian


def main():
    """
    Function main()
    :return:
    """
    print("SmartSocket.py - main() - Nothing to do")


if __name__ == "__main__":
    main()
