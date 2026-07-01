#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# keygen06.py -- reproduce OverRide level06's serial algorithm.
#
# Usage:
#   python2 keygen06.py <login>
#
# The login must be at least 6 characters. Prints the matching serial (the
# value the program computes in auth() and compares against your input).

import sys

def serial(login):
    n = len(login)
    if n < 6:
        sys.stderr.write("[!] login must be at least 6 characters\n")
        sys.exit(1)

    def signed(b):                       # emulate movsbl (sign-extend a byte)
        return b - 256 if b >= 128 else b

    # local_14 = (login[3] ^ 0x1337) + 0x5eeded
    acc = ((signed(ord(login[3])) ^ 0x1337) + 0x5eeded) & 0xffffffff

    for i in range(n):
        c = ord(login[i])
        if c < 0x20:                     # bytes below 0x20 abort with failure
            sys.stderr.write("[!] login contains a byte < 0x20\n")
            sys.exit(1)
        acc = (acc + ((signed(c) ^ acc) % 0x539)) & 0xffffffff

    return acc

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: python2 keygen06.py <login>\n")
        sys.exit(1)
    print(serial(sys.argv[1]))
