#!/usr/bin/python
import binascii
import struct


def get_packetname(ID):
    with open("./log.txt") as f:
        should_print = 0
         
        strid= binascii.b2a_hex(ID).upper() 
        strid = strid[2:4]+strid[0:2]

	for line in f:
            if line.startswith("ID:={num:0>8}".format(num=strid)):
                #print line
                next(f)
                return next(f)[14:-3]
#get_packetname("\xff\x00")
