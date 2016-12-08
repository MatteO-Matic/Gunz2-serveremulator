#!/usr/bin/env python
import socket
import select
import time
import sys
import binascii
import packet_crypt
import parselog
import re
import struct
import pprint
import array

def modrecv(self): 
    servername = ('54.193.89.40', 20100) 
    data = self.data
    hexdata = binascii.b2a_hex(data)
    show_output = 0
    show_data = 0
    show_data_decrypted = 1
    show_flags = 1
    show_decrypted = 1   
    sender = "server" if self.s.getpeername() == servername else "client"
    is_server = 1 if self.s.getpeername() == servername else 0
   
    if len(data) < 25: #assume it's a keep alive packet
        show_output = 0
        #handle_ping(self)
    elif data[16:18] =='\xfe\x10': #NTF_MATCH_PLAYER_COUNT
        show_output = 0
    elif data[16:18] == '\xec\04': #REQ_CHATTING_CHAT_CHANNEL
        show_output = 1
        show_decrypted=1
    elif data[16:18] == '\x24\x0e':
        show_output = 1
        show_decrypted = 1
    elif data[16:18] == '\x1C\x0C': #init packet (NTF_CONNECT_UFS)
        show_output = 1
        seed = struct.unpack("!H", data[41:43])
        packet_crypt.init_cryptkey(seed[0])
    else:
        show_output = 1


    if show_output:
        pID = binascii.b2a_hex(data[16:18])
        packet_header = "| S:{0} | L:{1} | {2} | ID:{3}".format(
                is_server, 
                len(data), 
                parselog.get_packetname(data[16:18]), 
                pID[3:4]+pID[0:2])
        
        print packet_header

        if show_flags:
            flags = struct.unpack("I", data[:4])
            print "flags: {0:b}".format(flags[0])
            print (flags[0] >> 3) & 1
        
        if show_data:
            t = iter(binascii.b2a_hex(self.data))
            pdata = " ".join(a+b for a,b in zip(t,t)) 
            print re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL)

        if show_data_decrypted:
            if packet_crypt.isInit:
                #edata = self.data.encode("hex")
                cdata = packet_crypt.decrypt(self.data[20:]) 
                t = iter(binascii.b2a_hex(cdata))
                pdata = " ".join(a+b for a,b in zip(t,t))
                print re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL)

        
        if show_decrypted:
            print '\n'+packet_crypt.decrypt_printsafe(data[20:]) #Don't include header
        # for i in range(0, len(pdata)/60):
        #     it = i*60
        #     it2 = i*20
        #     print re.sub("(.{85})", "\\1\n", pdata[it:it+60]+"     "+decrypteddata[it2:it2+20], re.DOTALL)

        print "\n"
    
def handle_ping(self):
    data = self.data
    show_output = 0

   # if sender == "client":
   #     print "Client"
   #     print (":".join("{:02x}".format(ord(c)) for c in data))
   #   own packt
    punknown = "\xa2\xd1\x27\xf3"
    pisping = "\x18"
    punknown2 ="\x00\x00\x00\x00\xf8\x3a\x0e"
    pcounter = data[12:18] 
    punknown3 = "\x00\x00\x33\x43\x54\xd1"
    
    pdata = punknown + pisping+ punknown2 +pcounter+punknown3
    
   # if(hex(ord(data[0])) == hex(ord(pdata[0]))):
    
    if(show_output):
        print "Swapping to forged packet"
        print (":".join("{:02x}".format(ord(c)) for c in pdata))
        print "--->"
        print (":".join("{:02x}".format(ord(c)) for c in data))
        print "\n"
    #self.data = pdata 
