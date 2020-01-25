#Hunter Schmidt, u0916776
# Version 0.1.0

from socket import *
from urlparse import urlparse
import re
from datetime import datetime
import sys

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
        client_socket.send(request.encode(encoding='ascii'))#TODO: Make sure this sends all data for large request
        response = receive_all(client_socket)
        #print response
        client_socket.close()
        return response

    def receive_all(the_socket):
        end_request='\r\n\r\n'
        message=[];data=''
        while True:
            data=the_socket.recv(1024)
            if End in message:
                break
            message.append(data)
        return ''.join(message)

# Represents the server side of the proxy
class server():

    port = 0
    # Starts the server's connection loop
    def start_server(self, port):
        self.port = port
        server_socket = socket(AF_INET,SOCK_STREAM)
        server_socket.bind(('',int(self.port)))
        server_socket.listen(1)
        print "Server listening on port: " + str(self.port)
        while True:
            try:
                connection_socket, addr = server_socket.accept()
                
                request = receive_all(connection_socket)
                #print "requested: " + request
            
                self.handle_request(connection_socket, request)
            except (KeyboardInterrupt, SystemExit):
                raise

    def receive_all(the_socket):
        end_request='\r\n\r\n'
        message=[];data=''
        while True:
            data=the_socket.recv(1024)
            if End in message:
                break
            message.append(data)
        return ''.join(message)
            

    def handle_request(self, connection_socket, request):
        c = client()
        urldata = self.parse_request(str(request))
        error_occured = urldata[0]

        if error_occured != True:
            hostname=urldata[1]
            port=urldata[2]
            path=urldata[3]
            headers = urldata[4]
            remote_request = "GET " + path +" HTTP/1.0\r\nHost: " + hostname +"\r\nConnection: close\r\n" #GET /~kobus/simple.html \r\nHost: http://www.cs.utah.edu/\r\nConnection: close\r\n\r\n
            for header in headers:                
                remote_request += header+"\r\n"
            remote_request+= "\r\n"
            remote_response = c.make_request(hostname, port, remote_request.encode(encoding='ascii'))

        else:
            remote_response = urldata[1]

        connection_socket.send(remote_response)#TODO: make this send all if larger than buffer

    # parses a request to determine the hostname and port (if no port is specified, assumes 80)
    def parse_request(self, request):
        #test_request="GET http://www.cs.utah.edu/~kobus/simple.html HTTP/1.0\r\nHost: www.cs.utah.edu\r\nConnection: close\r\nTest: test1\r\nTest2: test2\r\n\r\n"
        #test_not_implemented="POST http://test.com HTTP/1.0\r\n\r\n"

        error_message = self.determine_error(request)

        if error_message[0] != True:
            find_url = r"(?<=GET\s)\S*(?= HTTP)"
            url = re.findall(find_url, request)   
            
            headers=error_message[1]
            
            url_parser = urlparse(url.pop(0))
            hostname = url_parser.hostname
            port = url_parser.port
            path = url_parser.path
        
            if port is None:
                port=80
            tup = (False, hostname, port, path, headers)
            return(tup)
        
        
        return error_message

    def determine_error(self, request):
        has_error=False
        not_implemented = re.match("^(HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)", request)
        if not_implemented:
            error_message = "HTTP/1.0 501 Not Implemented\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") +"\r\nServer: PythonProxy/0.0.1\r\nConnection: Closed"
            has_error=True
        elif re.match("^GET", request) is None:
            error_message = "HTTP/1.0 400 Bad Request\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") +"\r\nServer: PythonProxy/0.0.1\r\nConnection: Closed"
            has_error=True
        else:
            headers = request.splitlines()
            headers.pop(0)
            headers_to_pass=[]
            for header in headers:
                if header !="" and header !="\"" and re.match("^\S+:\s\S+", header) is not None:
                    if re.match("^Connection: ", header) is None and re.match("^Host: ", header) is None:
                        headers_to_pass.append(header)
                else:
                    error_message = "HTTP/1.0 400 Bad Request\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") +"\r\nServer: PythonProxy/0.0.1\r\nConnection: Closed"
                    has_error=True
            has_error=False
            error_message=headers_to_pass

        return(has_error, error_message)




#creates and starts a server for the proxy
def main(argv):
    port=12345
    arguments = len(sys.argv)-1

    for i in range(1, arguments):
        if sys.argv[i] == "-h" or sys.argv[i] == "--help":
            print "Currently some telnet clients prepend all \ with \, causing a double escape. This breaks the parsing of the HTTP request. Normal browsers do not exhibit this behavior\nTry using -p <port> or --port <port> to specify the listening port without a prompt.\nIf no port is specified, defaults to 12345.\n"
            sys.exit()
        elif (sys.argv[i] == "-p" or sys.argv[i] == "--port") and i <= arguments:
            port = int(sys.argv[i+1])
            break
        else:
            print "Invalid arguments! type '-h' or '--help' for help.\n"
            sys.exit()
    s = server()
    s.start_server(port)


if __name__ == "__main__":
    main(sys.argv)


