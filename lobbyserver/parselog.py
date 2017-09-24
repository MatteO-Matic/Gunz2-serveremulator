#!/usr/bin/python
import binascii
import struct


def get_packetname(ID):
    with open("./log.txt") as f:
        ID = "{0:X}".format(ID)
        #strid= binascii.b2a_hex(ID).upper()
        #strid = strid[2:4]+strid[0:2]
        # print("ID:={num:0>8}".format(num=ID))
        for line in f:
            if line.startswith("ID:={num:0>8}".format(num=ID)):
                # print line
                next(f)
                return next(f)[14:-3]
# get_packetname(4351)
