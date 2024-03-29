#!/usr/bin/python
import binascii
import struct

_message = "\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0"
_cryptkey = ""
_cryptkeyfake = "\x57\x02\x5b\x04\xe1\x3c\x01\x08\x37\x0a\x12\x69\x41\x38\x0f\x78\x1b\x04\x24\x22\x43\x01\x49\x53\x50\x05\x13\x35\x4f\x02\x4d\x05"
#                               [------] Must get i4-5 from initial packet
isInit = 0

def init_cryptkey(seed):
    cryptkey = "\x57\x02\x5B\x04\x00\x00\x01\x08\x37\x0A\x12\x69\x41\x38\x0F\x78\x1B\x04\x24\x22\x43\x01\x49\x53\x50\x05\x13\x35\x4F\x02\x4D\x05"
    key = "\x34\x06"
    xored = seed ^ struct.unpack("!H", key)[0]
    packed = struct.pack("!H", xored)
    cryptkey = cryptkey[:4] + packed + cryptkey[6:]

    global _cryptkey
    _cryptkey = cryptkey
    global isInit
    isInit = 1
    print(binascii.b2a_hex(_cryptkey))


def singleencrypt(msg, key):
    wstr = "w"
    a = msg
    a = ord(a) ^ ord(key)
    a = a << 2

    #b = (a >> 8 | a) ^ 0xf0
    b = a >> 8
    b = b | (a & 0xFF)
    b = b ^ 0xF0
    wstr = wstr + "{:02x}".format(b)
    print(wstr)

def _encrypt(msgchar, cryptkey):
    newstring = ""
    for i, c in enumerate(msgchar):
        a = ord(c)
        # print "c: ",hex(a)
        # print "k: ", hex(ord(cryptkey[i%32]))
        # print "{:02x} : {:02x}".format(a, ord(cryptkey[i%32]))
        a ^= ord(cryptkey[i % 32])
        a <<= 2
        b = a >> 8
        b |= (a & 0xFF)
        b ^= 0xF0

        newstring += (chr(b))

    return newstring

def decrypt_printsafe(msgchar):
    if _cryptkey == "":
        print("cryptkey isn't set yet.")
        return ""
    plain = _decrypt(msgchar, _cryptkey)
    plainsafe = ""
    for c in plain:
        if ord(c) > 32 and ord(c) < 127:
            plainsafe += c
        else:
            plainsafe += "."
    return plainsafe


def decrypt(msgchar):
    if _cryptkey == "":
        print("cryptkey isn't set yet.")
        return ""
    return _decrypt(msgchar, _cryptkey)


def encrypt(msgchar):
    if _cryptkey == "":
        print("cryptkey isn't set yet.")
        return ""
    return _encrypt(msgchar, _cryptkey)


def _decrypt(msgchar, cryptkey):
    plaintext = ""
    for i, c in enumerate(msgchar):
        a = ord(c)
        a ^= 0x0F0
        b = (a & 3)
        a >>= 2
        b <<= 6
        b = (a | b)
        b ^= ord(cryptkey[i % 32])

        plaintext += (chr(b))
    return plaintext

def bruteforceOffset():
    for i in range(0, 50):
        plainstr = _decrypt(_message[i:], _cryptkeyfake)
        sout = ""
        print("")
        for c in plainstr:
            if ord(c) > 32 and ord(c) < 128:
                sout += c
            else:
                sout += "."
        #val = struct.unpack("I", plainstr[:4])
        #print (val)
        print("i:{0}  -".format(i), sout)
# bruteforceOffset()
# print decrypt(_message)
# bruteforceOffset()
