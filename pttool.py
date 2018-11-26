#!/usr/bin/python3

"""
# Authors:      Brandon Everhart
# Date:         11/26/2018
#
# Description:
#   - Pwntools api
#
# Changelog:
#   - 9/20 File created
#   - 11/26 Update
#
"""

import pwn


def docs():
    """

    :return:
    """
    print(__doc__)
    print(asm.__doc__)
    print(disasm.__doc__)


def disasm(filename):
    """
    """
    elf = pwn.ELF(filename)
    text_data = elf.get_section_by_name(".text").data()
    result = pwn.disasm(text_data)
    print(type(result))
    return result


def asm(file_mem):
    """
    """
    data = str(file_mem)[2:-3]
    result = str(pwn.asm(data))
    return result


if __name__ == "__main__":
    docs()
