#!/usr/bin/env python

import socket


TCP_IP = ''
TCP_PORT = 9090
BUFFER_SIZE = 8192

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

conn, addr = s.accept()
print 'Connection address:', addr
while 1:

    sdata = "\x02\x00\x00\x00\x14\x00\x00\x00\x00\x60\x07\x00\x00\x00\x00\x00\x05\x00\x00\x00"
    conn.send(sdata)
    
    data = conn.recv(BUFFER_SIZE)
    if not data: break
    print "\n"
    print(":".join("{:02x}".format(ord(c)) for c in data))
    #print "received data:", data
    print "\n"
    
    sdata = "\x02\x00\x00\x00\x18\x00\x00\x00\x00\x60\x07\x00\x00\x00\x00\x00\x07\x00\x00\x00\x44\x49\x57\xc3"
    conn.send(sdata)
    
    data = ""
    data = conn.recv(BUFFER_SIZE)
    if not data: break
    print "\n"
    print(":".join("{:02x}".format(ord(c)) for c in data))
    #print "received data:", data
    print "\n"

    sdata = "\x21\x30\x3c\x10\x31\x00\x00\x00\x00\x60\x07\x00\x03\xeb\xf1\x02\x1c\x0c\x44\x03\x1d\x00\x00\x00\x1c\x0c\x00\x00\x00\x10\x00\x01\x00\x67\xa6\x21\x20\x00\x00\x00\x00\xda\x0c\x00\x00\xdc\x10\x00\x00"
    conn.send(sdata) 

    sdata = "\x29\xc0\x4a\x10\xcd\x04\x00\x00\x00\xf0\x12\x0e\x12\xeb\xf1\x02\x26\x0c\x77\x00\x4b\xe8\x9d\xe0\xd3\xe8\xf4\xd0\x2c\x6a\xa8\x51\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\x69\x61\x5c\x78\xc0\x01\x40\x19\x24\x15\x2c\x49\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xd1\x90\xc1\x8e\x13\x16\xd8\xf4\xd0\x2c\x78\xb8\x50\xf5\x21\xcc\x20\x9c\xe5\x60\x59\xfd\xd9\xd5\xb8\xb1\x8d\xbc\x21\xcd\xcd\xc5\xe4\xad\x78\xd9\xa5\x5b\xff\xa2\xd4\x2c\xd8\xb8\x55\xf5\x5d\xd4\x11\x9c\x22\x70\x78\xfd\xf4\xd5\x7f\xa1\x26\xac\xe6\xdd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\x35\x7c\xd5\xf9\x09\x05\x40\x4c\xc1\x59\xd8\xdd\x35\xe9\xc9\x58\x79\xd8\x1c\x34\x5d\x05\xb1\x7c\xa9\x20\x25\x38\x70\x75\x68\x8f\x50\x44\x58\x35\x99\xf5\xdd\x1d\x98\x08\x99\x2c\x68\x79\xdd\x4c\x25\x40\x74\xf0\x61\x75\xf5\x68\x75\x10\x55\x28\x31\xc0\x41\xee\x15\x35\x45\xe5\x50\x50\xdd\x7d\xa0\x44\x20\x19\x2d\xb1\x75\x4c\x71\x18\x70\x39\x0c\x34\xe4\x45\x48\x4d\xd5\x28\x35\x4c\xed\x9e\x15\x25\x6d\x99\xed\x05\xc4\x7d\xf8\x44\xd9\x14\x50\xe8\x39\xd8\xcd\xc8\x35\x59\x6c\x78\xac\x7d\x70\x84\x2d\x08\x41\x4c\xed\xea\x5d\x25\x81\x89\x6d\x2d\x18\x24\x95\x79\xd0\x14\x08\xe8\xf0\x4d\x7c\x80\x98\xac\x31\x19\xb5\x58\x70\x2d\x6c\xfc\xad\xcc\xdd\x02\xfd\xf1\xe1\x51\xcd\x81\x44\x7d\xe5\xe4\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd8\xf4\xd0\x2c\xd8\xb8\x55\xf5\x10\xcc\x11\x9c\xe0\x60\x78\xfd\xf4\xd5\xbd\xb1\xe4\xbc\x24\xcd\xf8\xc5\xe4\xad\xf8\x9d\xe0\x4b\xd4\xf4\xd0\x2c\xe0\xb8\x55\xf5\x10\xcc\x11\x9c\xe4\x64\x78\xfd\xf0\xd5\xbd\xb1"
    conn.send(sdata)
       


    data = ""
    data = conn.recv(BUFFER_SIZE)
    if not data: break
    print "\n"
    print(":".join("{:02x}".format(ord(c)) for c in data))
    #print "received data:", data
    print "\n"
conn.close()