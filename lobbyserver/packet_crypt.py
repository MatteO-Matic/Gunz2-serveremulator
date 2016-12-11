#!/usr/bin/python
import binascii
import struct



#_message ="\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00\x61\x00x61"

#_message="\x09\x00\x5B\x0D\xC3\x00\x00\x00\x00\x00\x27\x04\x11\x00\x00\x00\xEC\x04\x1F\x6A\x13\xF8\x9D\xE0\x76\xDC\xF4\xF6\xD5\xD4\xB8\xDF\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x10\xCC"


#_message = "\xad\x7d\x9d\x65\x4f\xc9\xf4\x55\x2c\x5d\xb8\xd0\xf5\x95\xcc\x94\x9c\x65\x60\xfd\xfd\x71\xd5\x38\xb1\x61\xbc\xa1\xcd\x7d\xc5\x61\xad\x7d\x9d\x65\x4f\xc9\xf4\x55\x2c\x5d\xb8\xd0\xf5\x95\xcc\x94\x9c\x65\x60\xfd\xfd\x71\xd5\x38\xb1\x61\xbc\xa1\xcd\x7d\xc5\x61\xad\x7d\x9d\x65\x4f\xc9\xf4\x55\x2c\x5d\xb8\xd0\xf5\x95\xcc\x94\x9c\x65\x60\xfd\xfd\x71\xd5\x38\xb1\x61\xbc\xa1\xcd\x7d\xc5\x61\xad\x7d\x9d\x65\x4f\xc9\xf4\x55\x2c\x5d\xb8\xd0"

#_message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

_message = "\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0\xF5\x95\xCC\x94\x9C\x65\x60\xFD\xFD\x71\xD5\x38\xB1\x61\xBC\xA1\xCD\x7D\xC5\x61\xAD\x7D\x9D\x65\xC5\x49\xF4\x55\x2C\x5D\xB8\xD0"


_cryptkey = ""
#_57025b04e13c0108370a126941380f781b04242243014953500513354f024d05

_cryptkeyfake="\x57\x02\x5b\x04\xe1\x3c\x01\x08\x37\x0a\x12\x69\x41\x38\x0f\x78\x1b\x04\x24\x22\x43\x01\x49\x53\x50\x05\x13\x35\x4f\x02\x4d\x05"

#_message ="\x29\x98\x53\x2C\x64\x00\x00\x00\x00\x00\x00\x00\xD0\x05\x00\x00\x9C\x18\x9A\x2E\xEC\xF8\x9D\xE0\x74\x2C\xF4\xD5\x2C\xDC\xB8\x55\xF5\x10\xCC\x6F\x9C\xF4\x60\x78\xFD\xF4\xD5\xBD\xB1\xE4\xBC\x24\xCD\xF8\xC5\xE4\xAD\xF8\x9D\xE0\x06\x4C\xF4\xD0\x2C\xD8\xB8\xAE\x0A\xEF\x33\x11\x9C\xE0\x60\x78\x3A\x90\xD5\x8F\x64\xBB\x6D\xA6\x4F\x86\xC1\x24\xEF\x01\x37\xE9\x31\xC2\x51\xC3\xBC\x1E\xEE\x44\xB5\x10\xCC\x11"

#_cryptkeyfake = "\x57\x02\x5B\x04\x00\x00\x01\x08\x37\x0A\x12\x69\x41\x38\x0F\x78\x1B\x04\x24\x22\x43\x01\x49\x53\x50\x05\x13\x35\x4F\x02\x4D\x05"
#_cryptkey =  "\x57\x02\x5B\x04\xEF\x2F\x01\x08\x37\x0A\x12\x69\x41\x38\x0F\x78\x1B\x04\x24\x22\x43\x01\x49\x53\x50\x05\x13\x35\x4F\x02\x4D\x05"
#                               [------] Must get i4-5 from initial packet

isInit = 0

def init_cryptkey(seed):
    cryptkey =  "\x57\x02\x5B\x04\x00\x00\x01\x08\x37\x0A\x12\x69\x41\x38\x0F\x78\x1B\x04\x24\x22\x43\x01\x49\x53\x50\x05\x13\x35\x4F\x02\x4D\x05"
    key = "\x34\x06"
    xored = seed ^struct.unpack("!H", key)[0]
    packed = struct.pack("!H", xored) 
    cryptkey = cryptkey[:4]+packed+cryptkey[6:]
    
    global _cryptkey
    _cryptkey = cryptkey
    global isInit
    isInit= 1
    print (binascii.b2a_hex(_cryptkey))

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
        print (wstr)

#singleencrypt('\x61', '\x04')

def _encrypt(msgchar, cryptkey):
    newstring = ""
    for i, c in enumerate(msgchar):
        a = ord(c)
        # print "c: ",hex(a)
        #print "k: ", hex(ord(cryptkey[i%32]))
        # print "{:02x} : {:02x}".format(a, ord(cryptkey[i%32]))
        a ^= ord(cryptkey[i%32])
        a <<=2
        b = a >> 8
        b |= (a & 0xFF)
        b ^= 0xF0

        newstring += (chr(b))

    return newstring
        
def decrypt_printsafe(msgchar):
    if _cryptkey == "":
        print ("cryptkey isn't set yet.")
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
        print ("cryptkey isn't set yet.")
        return ""
    return _decrypt(msgchar, _cryptkey)

def encrypt(msgchar):
    if _cryptkey == "":
        print ("cryptkey isn't set yet.")
        return ""
    return _encrypt(msgchar, _cryptkey)

def _decrypt(msgchar, cryptkey):       
    plaintext = ""
    for i, c in enumerate(msgchar):
        a = ord(c)
        a ^= 0x0F0;
        b = (a & 3);
        a >>= 2;
        b <<= 6;
        b = (a | b);
        b ^= ord(cryptkey[i % 32]);
         
        plaintext += (chr(b))
    return plaintext


def dostuff():
    
    #print binascii.b2a_hex( _message)
    #nstr = encrypt(_message, _cryptkey)
    #print " ".join("{:02x}".format(ord(c)) for c in nstr)
    #plainstr = (local_decrypt(_message[20:], _cryptkeyfake))
    
    print  (_decrypt(_message, _cryptkeyfake).encode("hex"))
    
    
    #print s
    #something = struct.pack('c'"\xff\x11")
#dostuff() 

    #plainstr = encrypt("hello world\x00\x00\xf0", _cryptkeyfake)

    #print local_decrypt(plainstr, _cryptkeyfake)
    
    #encrypted = encrypt(plainstr, _cryptkeyfake)

    #print "\n\n\nencrypted again:"
    #print binascii.b2a_hex(encrypted) 
    
    #encrypted_again = encrypt(plainstr, _cryptkeyfake)
    #plain_again = local_decrypt(encrypted_again[20:], _cryptkeyfake)

def bruteforceOffset():
    for i in range (0, 50):
        plainstr = _decrypt(_message[i:], _cryptkeyfake) 
        sout = ""
        print ("")
        for c in plainstr:
            if ord(c)>32 and  ord(c) < 128:
                sout += c
            else:
                sout += "."
        #val = struct.unpack("I", plainstr[:4])
        #print (val)
        print ("i:{0}  -".format(i), sout)
#bruteforceOffset()
#print decrypt(_message)
#bruteforceOffset()
