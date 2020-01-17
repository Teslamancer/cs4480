#Hunter Schmidt, u0916776
# Version 0.0.1

from socket import *
from urlparse import urlparse
import re

class client():

    test_get = "GET http://www.cs.utah.edu/~kobus/simple.html HTTP/1.0\r\n\r\n"

    def make_request(self, hostname, port, request):
        server_name = hostname
        server_port = port
        client_socket = socket(AF_INET,SOCK_STREAM)
        client_socket.connect((server_name,server_port))        
        client_socket.send(request)
        response = client_socket.recv(1024)
        print response
        client_socket.close()
        return response

class server():

    port = 0
    #server_socket
    def start_server(self):
        self.port = input("Please enter the port number to listen on:\n")
        server_socket = socket(AF_INET,SOCK_STREAM)
        server_socket.bind(('',int(self.port)))
        server_socket.listen(1)
        print "Server listening on port: " + str(self.port)
        while True:
            connection_socket, addr = server_socket.accept()
            request = connection_socket.recv(1024).decode()
            print "requested: " + request
            c = client()
            urldata = self.parse_request(request)
            hostname=urldata[0]
            port=urldata[1]
            remote_response = c.make_request(hostname, port, request)

            connection_socket.send(remote_response)

    def parse_request(self, request):
        url = re.findall(r"[^GET ]\S*(?= HTTP\/1.0)",request)
        url_parser = urlparse(url.pop())
        hostname = url_parser.hostname
        port = url_parser.port
        if port is None:
            port=80
        tup = (hostname, port)
        return(tup)


s = server()
s.start_server()


