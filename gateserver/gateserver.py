#! /usr/bin/env python
import SimpleHTTPServer
import SocketServer
import os

os.chdir("./")
PORT = 3000

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

httpd = SocketServer.TCPServer(("", PORT), Handler)

print ("serving at port", PORT)
httpd.serve_forever()
