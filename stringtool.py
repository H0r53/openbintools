#!/usr/bin/python3
#
# Description:  This module defines a method called strings that identifies all strings within a bytearray.
#               The optional tolerance argument (default = 3) defines the number of consecutive characters
#               that constitute a string. Tabs and spaces are allowed; however, they are stripped from
#               the beginning and end of identified strings. All other whitespace and nonprintable characters
#               are ignored. Finally, the number of times an identified string occurs is prepended to the
#               final output.
#

from string import printable, whitespace

def strings(byte_array, tolerance=3):
    alpha = list(printable)
    for w in whitespace:
        if w not in ['\t',' ']:
            alpha.remove(w)

    strlist = {}
    mstr = ''
    for i in byte_array:
        if i in alpha:
            mstr += i
        elif i == '\x00':
            mstr = mstr.strip()
            if len(mstr) >= tolerance:
                if mstr in strlist:
                    strlist[mstr] += 1
                else:
                    strlist[mstr] = 1
            mstr = ''

    for k,v in strlist.iteritems():
        print("[{}] {}".format(v,k))
