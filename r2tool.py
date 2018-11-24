#!/usr/bin/python3

"""
Tool to interact with r2

choices=["-f", "-i", "-ll", "-m", "-p", "-s", "-ss"])
"""

import pipetool
import r2pipe
import json


def functions(file):
    return pipetool.exec_quiet(["rabin2", "-s", file])


def imports(file):
    return pipetool.exec_quiet(["rabin2", "-i", file])


def linkedlibs(file):
    return pipetool.exec_quiet(["rabin2", "-l", file])


def mainaddr(file):
    return pipetool.exec_quiet(["rabin2", "-M", file])


def pipe(cmd, file):
    r2 = r2pipe.open(file)
    r2.cmd("aaaa")
    return r2.cmd(cmd[2:-1])


def secuity(file):
    data = json.loads(pipetool.exec_quiet(["rabin2", "-Ij", file]))
    nx = data['info']['nx']
    pic = data['info']['pic']
    relro = data['info']['relro']
    strip = data['info']['stripped']
    canary = data['info']['canary']
    result = "Security:\nnx:\t{}\npic:\t{}\nrelro:\t{}\nstrip:\t{}\ncanary:\t{}".format(nx, pic, relro, strip, canary)
    return result


def sections(file):
    return pipetool.exec_quiet(["rabin2", "-S", file])


def debug():
    functions(file)
    imports(file)
    linkedlibs(file)
    mainaddr(file)
    pipe("afl", file)


if __name__ == "__main__":
    debug()
