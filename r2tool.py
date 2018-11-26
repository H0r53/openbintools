#!/usr/bin/python3

"""
    File:
        - r2tool.py

    Authors:
        - Jacob Mills,
        - Brandon Everhart,
        - Taylor Shields

    Date: 11/25/2018

    Description:
        - Tool to interact with r2
        - Choices=[
            "-f" - Return functions/symbols,
            "-i" - Return Imports
            "-l" - Return Linked Libraries,
            "-m" - Return main address,
            "-p" - Return result of piped cmd,
            "-s" - Return securities,
            "-ss" - Return sections
        ]

    Changelog:
        - 11/24 Documented
        - 11/24 Cleaned formatting based on PyCharm, PyLint3, PEP8
        - 11/24 Pylint score -1.18/10 --> 3.33/10
        - 11/25 Pylint score 3.33/10 --> 10.00/10
"""

import json
import r2pipe
import pipetool


def docs():
    """
    Function:
        r2tool.docs()

        Description:
            Prints all docstrings related to this file.

        Parameters:
            - None

        Return:
            - None
    """
    print(__doc__)
    print(docs.__doc__)
    print(functions.__doc__)
    print(imports.__doc__)
    print(linkedlibs.__doc__)
    print(mainaddr.__doc__)
    print(pipe.__doc__)
    print(secuity.__doc__)
    print(sections.__doc__)


def functions(file):
    """
    Function:
        r2tool.functions()

    Description:
        - Utilizes pipetool.py to execute the rabin2 utility
        to return the symbols found in the file.

    Parameters:
        - file:
            Description - specified file to analyze,
            Data Type - string,
            Requirement - mandatory,
            Argument Type - Positional (1st)

    Return:
        - pipetool.exec_quiet(["rabin2", "-s", file]):
            Description - stdout of the rabin2 process with the -s argument
            Data Type - string
    """
    return pipetool.exec_quiet(["rabin2", "-s", file])


def imports(file):
    """
    Function:
        r2tool.imports()

    Description:
        - Utilizes pipetool.py to execute the rabin2 utility
         to return the imports found in the file.

    Parameters:
        - file:
            Description - specified file to analyze,
            Data Type - string,
            Requirement - mandatory,
            Argument Type - Positional (1st)

    Return:
        - pipetool.exec_quiet(["rabin2", "-i", file]):
            Description - stdout of the rabin2 process with the -i argument
            Data Type - string
    """
    return pipetool.exec_quiet(["rabin2", "-i", file])


def linkedlibs(file):
    """
    Function:
        r2tool.linkedlibs()

    Description:
        - Utilizes pipetool.py to execute the rabin2 utility
         to return the linked libraries found in the file.

    Parameters:
        - file:
            Description - specified file to analyze,
            Data Type - string,
            Requirement - mandatory,
            Argument Type - Positional (1st)

    Return:
        - pipetool.exec_quiet(["rabin2", "-l", file]):
            Description - stdout of the rabin2 process with the -l argument
            Data Type - string
    """
    return pipetool.exec_quiet(["rabin2", "-l", file])


def mainaddr(file):
    """
    Function:
        r2tool.mainaddr()

    Description:
        - Utilizes pipetool.py to execute the rabin2 utility
         to return the main address found in the file.

    Parameters:
        - file:
            Description - specified file to analyze,
            Data Type - string,
            Requirement - mandatory,
            Argument Type - Positional (1st)

    Return:
        - pipetool.exec_quiet(["rabin2", "-M", file]):
            Description - stdout of rabin2 with the -M argument
            Data Type - string
    """
    return pipetool.exec_quiet(["rabin2", "-M", file])


def pipe(cmd, file):
    """
    Function:
       r2tool.pipe()

    Description:
        - Pipes user's requested command to radare2 for specified file

    Parameters:
        - cmd:
            Description - list where first two elements are "r" and "p"
             and the remaining elements are commands to be passed to radare2,
            Data Type - list,
            Requirement - mandatory,
            Argument Type - Positional (1st)
        -file:
            Description - specified file to analyze,
            Data Type - string,
            Requirement - mandatory,
            Argument Type - Positional (2nd)

    Return:
        - radare2.cmd(cmd[2:-1]):
            Description - result of the requested radare2 command
            Data Type - string
    """
    radare2 = r2pipe.open(file)
    radare2.cmd("aaaa")
    result = radare2.cmd(cmd[2:-1])
    radare2.quit()
    return result


def security(file):
    """
    Function:
        r2tool.security()

    Description:
        - Outputs info on the security features for the specified file

    Parameters:
        - file:
            Description - specified file to analyze,
            Data Type - string,
            Requirement - mandatory,
            Argument Type - Positional (1st)

    Return:
        - result:
            Description - string containing info about security features for specified file
            Data Type - string
    """
    data = json.loads(pipetool.exec_quiet(["rabin2", "-Ij", file]))
    nonexe = data['info']['nx']
    pic = data['info']['pic']
    relro = data['info']['relro']
    strip = data['info']['stripped']
    canary = data['info']['canary']
    result = "Security:\nnx:\t{}\npic:\t{}\nrelro:\t{}\nstrip:\t{}\ncanary:\t{}".format(
        nonexe,
        pic,
        relro,
        strip,
        canary
    )
    return result


def sections(file):
    """
    Function:
        r2tool.sections()

    Description:
        - Utilizes pipetool.py to execute the rabin2 utility
         to return the sections found in the file.

    Parameters:
        - file:
            Description - specified file to analyze,
            Data Type - string,
            Requirement - mandatory,
            Argument Type - Positional (1st)

    Return:
        - pipetool.exec_quiet(["rabin2", "-S", file]):
            Description - stdout of rabin2 with the -S argument
            Data Type - string
    """
    return pipetool.exec_quiet(["rabin2", "-S", file])


if __name__ == "__main__":
    docs()
