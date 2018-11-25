#!/usr/bin/python3

"""
    File:
        - stringtool.py

    Authors:
        - Jacob Mills,
        - Brandon Everhart

    Date: 11/24/2018

    Description:
        - This module defines a method called strings that identifies all strings within
        a bytearray. The optional tolerance argument (default = 3) defines the number of
        consecutive characters that constitute a string. Tabs and spaces are allowed;
        however, they are stripped from the beginning and end of identified strings. All
        other whitespace and nonprintable characters are ignored. Finally, the number of
        times an identified string occurs is prepended to the final output.

        if __name__ == "__main__":
            docs()

    Changelog:
        - 11/24 Documented
        - 11/24 Cleaned formatting based on PyCharm, PyLint3, PEP8
        - 11/24 PyLint score ??? --> 10.00/10
"""

from string import printable, whitespace


def docs():
    """
    Function:
        stringtool.docs()

        Description:
            Prints all docstrings related to this file.

        Parameters:
            - None

        Return:
            - None
    """
    print(__doc__)
    print(docs.__doc__)
    print(strings.__doc__)


def strings(byte_array, tolerance=3):
    """
    Function:
        stringtool.strings()

        Description:
            - Loop throw a byte array and store strings which meet the specified tolerance in
            a dictionary. Uses the dictionary to store the string as a key along with its count, the
            number of times the string has been seen, as the value.

        Parameters:
            - byte_array:
                Description - path to target file,
                Data Type - string,
                Requirement - mandatory,
                Argument Type - positional(1st)
            - tolerance:
                Description - length of contiguous ascii characters to be consider a string
                Data Type - integer
                Requirement - Optional(default=3)
                Argument Type - positional(2nd)

        Return:
            - None
    """
    alpha = list(printable)
    for char in whitespace:
        if char not in ['\t', ' ']:
            alpha.remove(char)

    strlist = {}
    mstr = ''
    for byte in byte_array:
        if chr(byte) in alpha:
            mstr += chr(byte)
        elif byte == 0x0:
            mstr = mstr.strip()
            if len(mstr) >= tolerance:
                if mstr in strlist:
                    strlist[mstr] += 1
                else:
                    strlist[mstr] = 1
            mstr = ''

    for key, value in strlist.items():
        print("[{}] {}".format(value, key))


if __name__ == "__main__":
    docs()
