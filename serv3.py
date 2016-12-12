#!/usr/bin/env python
import socket
import time
import binascii
import struct
import re


def printdata(data):

    t = iter(binascii.b2a_hex(data))
    pdata = " ".join(a+b for a,b in zip(t,t)) 
   
    print_data = (re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL))
    print (print_data)

TCP_IP = ''
TCP_PORT = 9090
BUFFER_SIZE = 8192

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

conn, addr = s.accept()
print ('Connection address:', addr)
while 1:

    sdata = "\x02\x00\x00\x00\x14\x00\x00\x00\x00\x60\x07\x00\x00\x00\x00\x00\x05\x00\x00\x00"
    conn.send(sdata)
    
    data = conn.recv(BUFFER_SIZE)
    if not data: break
   
    printdata(data)

    millis = int((time.time() * 1000))
    #millis = millis + 2686079995+103+8+5#2686079745
    #millis = millis + 2686080000#2686079745
    htime = (binascii.hexlify(struct.pack('I', int((str(millis)[3:])))))
    
    
    #007 
    sdata = "\x02\x00\x00\x00\x18\x00\x00\x00\x00\x98\x07\x00\x00\x00\x00\x00\x07\x00\x00\x00" + htime.encode("hex")
    conn.send(sdata)
    
    data = ""
    data = conn.recv(BUFFER_SIZE)
    if not data: break 
    printdata(data)
    
    #ntf_connect_ufs
    sdata = "\x21\x88\x78\x0d\x31\x00\x00\x00\x00\xf8\x3a\x0e\x21\xf1\x93\x03\x1c\x0c\x30\x04\x1d\x00\x00\x00\x1c\x0c\x00\x00\x00\x10\x00\x01\x00\xe8\xe4\x21\x20\x00\x00\x00\x00\xa8\x5b\x00\x00\xed\x0f\x00\x00"

    conn.send(sdata) 

    
    
    data = ""
    data = conn.recv(BUFFER_SIZE)
    if not data: break
    printdata(data)


conn.close()

