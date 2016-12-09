#!/usr/bin/python
import socket
import select
import time
import sys
import binascii
import recvmod

buffer_size = 16384
delay = 0.00001
forward_to = ('54.193.89.40', 20100)
fo = open("foo.txt", "rw+")
serving_port = 9090

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception as e:
            print (e)
            return False

class TheServer:
    input_list = []
    channel = {}
    packet_count = 0

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)

    def main_loop(self):
        self.input_list.append(self.server)
        print ("Serving on port {0} to {1}:{2}".format(serving_port,forward_to[0], forward_to[1]))
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        if forward:
            print (clientaddr, "has connected")
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print ("Can't establish connection with remote server.")
            print ("Closing connection with client side", clientaddr)
            clientsock.close()

    def on_close(self):
        print (self.s.getpeername(), "has disconnected")
        #remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        global recvmod
        recvmod = reload(recvmod)
        
        recvmod.modrecv(self)
        data = self.data
        self.channel[self.s].send(data)

        # here we can parse and/or modify the data before send forward
       # hexdata = binascii.b2a_hex(data)
        
       # cmddata = hexdata[0:23]
       # if cmddata == "020000001800000000000000": 
       #     packetcounter = hexdata[24:31]
       #     isclient = hexdata[32:33]
       #     unknownflags = hexdata[34:39]
       #     checksum = hexdata[40:47]
       #     print cmddata+packetcounter+isclient+unknownflags+checksum
       #     print "\n"
       # else: 
       #     print ("{}".format(self.s))
       #     print ("PacketN: {}".format(self.packet_count))
       #     print (":".join("{:02x}".format(ord(c)) for c in data))
       #     print "\n"

       # self.packet_count+=1
       # self.channel[self.s].send(data)
    
       # 02:00:00:00:18:00:00:00:00:00:00:00:56:00:00:00:01:00:00:00:aa:13:4c:c6
       #[-----------------------------------][---------] |           [----------]
       #          Same every session         |           |             checksum?
       #                                     |           |
       #                Packet_counter(start 0) increment|
       #                righthandside after FF           |
       #                                                 |
       #                                                1 client; 0 host



if __name__ == '__main__':
        server = TheServer('', serving_port)
        try:
            server.main_loop()
        except KeyboardInterrupt:
            fo.close()
            print ("Ctrl C - Stopping server")
sys.exit(1)
