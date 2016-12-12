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
import array
import zlib
import string
import datetime 

class flags:
    def __init__(self, rawflags):
        #setup flags 
        self.is_normal = (rawflags >> 0) & 1
        self.is_ping = (rawflags >> 1) & 1
        self.unk = (rawflags >> 2) & 1
        self.is_encrypted = (rawflags >> 3) & 1
        self.is_compressed = (rawflags >> 4) & 1

class Gunz2Packet:
    def __init__(self, data):
        pass
    
    def save_tofile(self, fname):
        with open("out/{0}".format(fname) , 'w') as f:
            read_data = f.read()


def modrecv(self):
    servername = ('54.193.89.40', 20100) 
    data = self.data
    
    show_output = 0
    show_data = 0
    show_data_decrypted = 0
    show_flags = 1
    show_decrypted_text = 1

    save_tofile = 1
    
    sender = "server" if self.s.getpeername() == servername else "client"
    is_server = 1 if self.s.getpeername() == servername else 0
    
    #unpack packet header
    rawflags, hsize  = struct.unpack("II", data[:8])


    hflags = flags(rawflags) 
    
    show_data_decrypted = hflags.is_encrypted
    show_data = not hflags.is_encrypted
    
    #show_data = 1
    #show_data_decrypted = 0
    
    emulate_packet(self)

    if len(data) < 25: #assume it's a keep alive packet
        show_output =1 
        #handle_ping(self)
    elif data[16:18] == '\x06\x00': #NTF_AUTH_FAILED
        show_output = 1
    elif data[16:18] == '\x08\x00': #Some initial from client
        show_output =1
    elif data[16:18] =='\xfe\x10': #NTF_MATCH_PLAYER_COUNT
        show_output = 0
    elif data[16:18] == '\xec\04': #REQ_CHATTING_CHAT_CHANNEL
        show_output = 1
    elif data[16:18] == '\x24\x0e':
        show_output = 1
    elif data[16:18] == '\x1C\x0C': #init packet (NTF_CONNECT_UFS)
        show_output = 1
        seed = struct.unpack("!H", data[41:43])
        packet_crypt.init_cryptkey(seed[0])
    else:
        show_output = 1
    
    
    if show_output:
        #Socket data
        socket_info = "SData | S:{0} | L:{1}".format(
                is_server,
                len(data))
        print (socket_info)

        
        #Header data
        pID = binascii.b2a_hex(data[16:18])
        pID_name= parselog.get_packetname(data[16:18])
        packet_header =  "Hdata | Size:{2} | PID: {1}({0})".format(
                pID_name, 
                pID[3:4]+pID[0:2],
                hsize)
    
        print (packet_header)
        


        #Print binary flags
        if show_flags: 
            print_flags = "Flags | Normal:{0} | Ping:{1} | Encrypted:{2} | Compressed:{3} |".format(
                    hflags.is_normal, 
                    hflags.is_ping,
                    hflags.is_encrypted,
                    hflags.is_compressed
                    )
            print ("{0:b}".format(rawflags))
            print (print_flags)

        if show_data:
            t = iter(binascii.b2a_hex(data))
            pdata = " ".join(a+b for a,b in zip(t,t)) 
           
            print_data = (re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL))
            print (print_data)

        if show_data_decrypted:
            if packet_crypt.isInit:
                #show header without decrypting
                t = iter(binascii.b2a_hex(data[:20]))
                hdata = " ".join(a+b for a,b in zip(t,t)) 
                print (re.sub("(.{60})", "\\1\n", hdata, 0, re.DOTALL))
                print ("-----")
                cdata = packet_crypt.decrypt(data[20:])


                if hflags.is_compressed:
                    decdata= (zlib.decompress(cdata[4:]))
                    t = iter(binascii.b2a_hex(decdata))
                    pdata = " ".join(a+b for a,b in zip(t,t))
                    #Print packet data 
                    print_data =  re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL)
                    print (print_data)
                else:
                    t = iter(binascii.b2a_hex(cdata))
                    pdata = " ".join(a+b for a,b in zip(t,t))
                    #Print packet data 
                    print_data = (re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL))
                    print (print_data)
                #printing out payload 
                #plength = struct.unpack("I", cdata[:4])
                #print (plength)

        
        if show_decrypted_text:
            if hflags.is_compressed:
                decdata= zlib.decompress(cdata[4:])
                   
                print_plain =  ("".join((c if (c in string.printable) else '.') for c in decdata))
                print (print_plain)
            else:
                print_plain = ('\n'+packet_crypt.decrypt_printsafe(data[20:])) #Don't include header
                print (print_plain)

        print ("\n")

        if save_tofile:
            with open("out/{0}".format(pID_name) , 'a+') as f:
                f.write("\n")
                f.write("\n")
                f.write(socket_info)
                f.write("\n")
                f.write(packet_header)
                f.write("\n")
                f.write ("{0:b}".format(rawflags))
                f.write("\n")
                f.write(print_flags)
                f.write("\n")
                f.write(print_data)
                f.write("\n")
                f.write(print_plain)
                f.write("\n")


def emulate_packet(self):
    data = self.data

    #Rememeber to emulate NTF_HOLEPUNCHING_RESULT later
    pID = data[16:18]

    if pID == '\x06\x00': #NTF_AUTH_FAILED C
        pass
    elif pID == '\x07\x00': 
        #move along, nothing to see here 
        millis = int((time.time() * 1000))
        millis = millis + 2686079995+103+8+5#2686079745
        #millis = millis + 2686080000#2686079745
        htime = (binascii.hexlify(struct.pack('I', int((str(millis)[3:])))))

        #self.data=""
        #t = iter(binascii.b2a_hex(data))
        #pdata = " ".join(a+b for a,b in zip(t,t)) 
       
        #print_data = (re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL))
        #print (print_data)

        #print (htime)
        #self.data = "\x02\x00\x00\x00\x18\x00\x00\x00\x00\x98\x07\x00\x00\x00\x00\x00\x07\x00\x00\x00"+htime.encode("hex")


    else:
        pass
    

    

def handle_ping(self):
    data = self.data

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
        print ("Swapping to forged packet")
        print (":".join("{:02x}".format(ord(c)) for c in pdata))
        print ("--->")
        print (":".join("{:02x}".format(ord(c)) for c in data))
        print ("\n")
    #self.data = pdata 
