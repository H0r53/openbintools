#!/usr/bin/python3

"""
    File:
        - pipetool.py

    Authors:
        - Jacob Mills,
        - Brandon Everhart,
        - Taylor Shields

    Date: 11/24/2018

    Description:
        - Utility to execute external processes inside of a subprocess
         with the ability to specify stdin and stdout.

    Changelog:
        - 11/24 Documented
        - 11/24 Cleaned formatting based on PyCharm, PyLint3, PEP8
        - 11/24 Pylint score 1.00/10 --> 10.00/10
"""

import subprocess


def docs():
    """
    Function:
        pipetool.docs()

        Description:
            Prints all docstrings related to this file.

        Parameters:
            - None

        Return:
            - None
    """
    print(__doc__)
    print(docs.__doc__)
    print(exec_quiet.__doc__)


def exec_quiet(cmd, stdin_filename=None):
    """
    Function:
        pipetool.exec_quiet()

    Description:
        - Executes supplied commands in a subprocess and retrieves the
         stdout of that subprocess for our return value.
        -If an input file is specified, open the input file and supply
         it as stdin to the subprocess.

    Parameters:
        - cmd:
            Description - process to execute with its arguments,
            Data Type - list,
            Requirement - mandatory,
            Argument Type - Positional (1st)
        -stdin_filename:
            Description - specified file path for stdin,
            Data Type - string,
            Requirement - optional(default=None),
            Argument Type - Positional (2nd)

    Return:
        - output:
            Description - stdout of the executed process
            Data Type - string
    """
    output = ''
    if stdin_filename:
        pipe_in = open(stdin_filename, 'rb')
        proc1 = subprocess.Popen(cmd, stdin=pipe_in, stdout=subprocess.PIPE)
        output = proc1.stdout.read().decode('utf-8')
    else:
        proc1 = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        output = proc1.stdout.read().decode('utf-8')

    return output


if __name__ == "__main__":
    docs()
