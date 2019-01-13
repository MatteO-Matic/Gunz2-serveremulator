#!/usr/bin/env python
import socket
import time
import binascii
import struct
import re
import gunz2packet
import packet_crypt


def printdata(data):
    t = iter(binascii.b2a_hex(data))
    pdata = " ".join(a + b for a, b in zip(t, t))

    print_data = (re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL))
    print(print_data)


def on_recv(data):
    printdata(data)

    if data[16:18] == '\x06\x00':  # NTF_AUTH_FAILED
        p = gunz2packet.NONE_007()
        print("send time")
        conn.send(p.data)
        pass

    elif data[16:18] == '\x08\x00':  # Some initial from client
        print("ntf_connect_ufs (cryptkeyset)")
        p = gunz2packet.NTF_CONNECT_UFS()
        conn.send(p.data)

        #sdata = "\x21\x88\x78\x0d\x31\x00\x00\x00\x00\xf8\x3a\x0e\x21\xf1\x93\x03\x1c\x0c\x30\x04\x1d\x00\x00\x00\x1c\x0c\x00\x00\x00\x10\x00\x01\x00\xe8\xe4\x21\x20\x00\x00\x00\x00\xa8\x5b\x00\x00\xed\x0f\x00\x00"

        ## set key
        #seed = struct.unpack("!H", sdata[41:43])
        #packet_crypt.init_cryptkey(seed[0])
        #conn.send(sdata)

    elif data[16:18] == '\x03\xe8':  # REQ_LOGIN

        print("sending ack_login")
        p = gunz2packet.ACK_LOGIN()
        conn.send(p.data)

    elif data[16:18] == '\xfe\x10':  # NTF_MATCH_PLAYER_COUNT
        pass
    elif data[16:18] == '\xec\04':  # REQ_CHATTING_CHAT_CHANNEL
        pass
    elif data[16:18] == '\x24\x0e':
        pass
    else:
        pass

TCP_IP = ''
TCP_PORT = 9090
BUFFER_SIZE = 8192

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

while True:

 #   millis = int((time.time() * 1000))
 #  # millis = millis + 2686079995+103+8+5 %4294967295#2686079745
 #   htime = (binascii.hexlify(struct.pack('I', int((str(millis)[4:])))))
 #   sdata = "\x02\x00\x00\x00\x18\x00\x00\x00\x00\x98\x07\x00\x00\x00\x00\x00\x07\x00\x00\x00" + htime.decode("hex")

 #   print (binascii.b2a_hex(sdata))
 #   if True:
 #       break

    conn, addr = s.accept()
    print('Connection address:', addr)

    try:
        print("Connected: {0}".format(addr))

        print("NTF_HOLEPUNCHING_RESULT")

        p = gunz2packet.NTF_HOLEPUNCHING_RESULT()
        conn.send(p.data)
        while True:
            print("\n")

            data = conn.recv(8)
            if len(data) == 0:
                conn.close()
                break

            rawflags, hsize = struct.unpack("II", data[:8])

            # Gather full packet
            while len(data) < hsize:
                packet = conn.recv(hsize - len(data))
                if not packet:
                    continue
                data += packet

            if len(data) == 0:
                conn.close()
                break
            else:
                on_recv(data)
    finally:
        conn.close()


#    data = conn.recv(BUFFER_SIZE)
#    if not data: break
#
#    printdata(data)
#
#    millis = int((time.time() * 1000))
#    #millis = millis + 2686079995+103+8+5#2686079745
#    #millis = millis + 2686080000#2686079745
#    htime = (binascii.hexlify(struct.pack('I', int((str(millis)[3:])))))
#
#
#    #007
#    sdata = "\x02\x00\x00\x00\x18\x00\x00\x00\x00\x98\x07\x00\x00\x00\x00\x00\x07\x00\x00\x00" + htime.encode("hex")
#    conn.send(sdata)
#
#    data = ""
#    data = conn.recv(BUFFER_SIZE)
#    if not data: break
#    printdata(data)
#
#
#
#
#    data = ""
#    data = conn.recv(BUFFER_SIZE)
#    if not data: break
#    printdata(data)


conn.close()
