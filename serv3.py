#!/usr/bin/env python

import socket

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
    print ("\n")
    print(":".join("{:02x}".format(ord(c)) for c in data))
    #print "received data:", data
    print ("\n")
    

    millis = int((time.time() * 1000))
    #millis = millis + 2686079995+103+8+5#2686079745
    #millis = millis + 2686080000#2686079745
    htime = (binascii.hexlify(struct.pack('I', int((str(millis)[3:])))))
    
    sdata = "\x02\x00\x00\x00\x18\x00\x00\x00\x00\x98\x07\x00\x00\x00\x00\x00\x07\x00\x00\x00" + htime.encode("hex")
    conn.send(sdata)
    
    data = ""
    data = conn.recv(BUFFER_SIZE)
    if not data: break
    print ("\n")
    print(":".join("{:02x}".format(ord(c)) for c in data))
    #print "received data:", data

    print ("\n")
    sdata = "\x21\x30\x3c\x10\x31\x00\x00\x00\x00\x60\x07\x00\x03\xeb\xf1\x02\x1c\x0c\x44\x03\x1d\x00\x00\x00\x1c\x0c\x00\x00\x00\x10\x00\x01\x00\x67\xa6\x21\x20\x00\x00\x00\x00\xda\x0c\x00\x00\xdc\x10\x00\x00"
    conn.send(sdata) 

    conn.send(sdata)
       


    data = ""
    data = conn.recv(BUFFER_SIZE)
    if not data: break
    print ("\n")
    print(":".join("{:02x}".format(ord(c)) for c in data))
    #print "received data:", data
    print ("\n")
conn.close()
