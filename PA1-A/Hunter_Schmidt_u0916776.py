#Hunter Schmidt, u0916776
# Version 0.0.1

from socket import *
from urlparse import urlparse
import re

# Represents the client side of the proxy
class client():

    test_get = "GET http://www.cs.utah.edu/~kobus/simple.html HTTP/1.0\r\n\r\n"
    test_multiline =u"GET /~kobus/simple.html HTTP/1.0\r\nHost: www.cs.utah.edu\r\nConnection: close\r\n\r\n"
    #GET http://www.google.com HTTP/1.0\r\n\r\n

    #sends a request to the provided hostname on the provided port, and returns the response (if any)
    def make_request(self, hostname, port, request):
        server_name = hostname
        server_port = port
        client_socket = socket(AF_INET,SOCK_STREAM)
        client_socket.connect((server_name,server_port))     
        #request = self.test_multiline
        client_socket.send(request.encode(encoding='ascii'))
        response = client_socket.recv(1024)
        print response
        client_socket.close()
        return response

# Represents the server side of the proxy
class server():

    port = 0
    # Starts the server's connection loop
    def start_server(self):
        self.port = input("Please enter the port number to listen on:\n")
        server_socket = socket(AF_INET,SOCK_STREAM)
        server_socket.bind(('',int(self.port)))
        server_socket.listen(1)
        print "Server listening on port: " + str(self.port)
        while True:
            connection_socket, addr = server_socket.accept()
            request = connection_socket.recv(1024)
            print "requested: " + request
            
            self.handle_request(connection_socket, request)
            

    def handle_request(self, connection_socket, request):
        c = client()
        urldata = self.parse_request(str(request))
        hostname=urldata[0]
        port=urldata[1]
        path=urldata[2]
        headers = urldata[3]
        remote_request = "GET " + path +" HTTP/1.0\r\nHost: " + hostname +"\r\nConnection: close\r\n" #GET /~kobus/simple.html \r\nHost: http://www.cs.utah.edu/\r\nConnection: close\r\n\r\n
        for header in headers:
            if header !="" and re.match("^Connection: ", header) is None and re.match("^Host: ", header) is None and header !="\"":
                remote_request += header+"\r\n"
        remote_request+= "\r\n"
        remote_response = c.make_request(hostname, port, remote_request.encode(encoding='ascii'))
        connection_socket.send(remote_response)

    # parses a request to determine the hostname and port (if no port is specified, assumes 80)
    def parse_request(self, request):
        #test_request="GET http://www.cs.utah.edu/~kobus/simple.html HTTP/1.0\r\nHost: www.cs.utah.edu\r\nConnection: close\r\nTest: test1\r\nTest2: test2\r\n\r\n"
        find_url = r"[^GET ]\S*(?= HTTP)"
        url = re.findall(find_url, request)      
        url_parser = urlparse(url.pop(0))
        hostname = url_parser.hostname
        port = url_parser.port
        path = url_parser.path
        
        headers = request.splitlines()
        headers.pop(0)
        if port is None:
            port=80
        tup = (hostname, port, path, headers)
        return(tup)




s = server()
s.start_server()


