#!/usr/bin/python3
import subprocess

def exec_quiet(cmd,stdin_filename = None):
    output = ''
    if (stdin_filename):
        pipe_in = open(stdin_filename,'rb')
        p1 = subprocess.Popen(cmd,stdin=pipe_in, stdout=subprocess.PIPE)
        output = p1.stdout.read().decode('utf-8')
    else:
        p1 = subprocess.Popen(cmd,stdout=subprocess.PIPE)
        output = p1.stdout.read().decode('utf-8')

    return output
