#Hunter Schmidt, u0916776
# Version 1.0.0
from socket import *
from urlparse import urlparse
import re
from datetime import datetime
import argparse
from threading import Thread
import hashlib
import json
import requests

# Represents the client side of the proxy
class client():

    test_get = "GET http://www.cs.utah.edu/~kobus/simple.html HTTP/1.0\r\n\r\n"
    test_multiline = u"GET /~kobus/simple.html HTTP/1.0\r\nHost: www.cs.utah.edu\r\nConnection: close\r\n\r\n"
    #GET http://www.google.com HTTP/1.0\r\n\r\n

    #sends a request to the provided hostname on the provided port, and returns
    #the response (if any)
    def make_request(self, hostname, port, request):
        server_name = hostname
        server_port = port
        client_socket = socket(AF_INET,SOCK_STREAM)
        client_socket.connect((server_name,server_port))     
        #request = self.test_multiline
        client_socket.sendall(request.encode(encoding='ascii'))
        #response = client_socket.recv(2048)
        response = client.receive_all(client_socket)
        full_message = response[0]
        body=response[1]
        md5 = hashlib.md5(body).hexdigest()
        if(client.isVirus(md5)):
            return "HTTP/1.0 200 OK\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\nServer: PythonProxy/0.0.1\r\nConnection: Closed\r\nContent-Type: text/html\r\nContent-Length: 46\r\n" + "<html><h>File contained known virus</h></html>"
        #print response
        client_socket.close()
        return full_message

    @staticmethod
    def isVirus(md5):
        
        #query='GET \ https://www.virustotal.com/vtapi/v2/file/report?apikey=a17b64078af8488b98ad0f59ac9ce7e25fbf9ba8f811c96f5ed77d0db1bee9cf&resource='+md5
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': 'a17b64078af8488b98ad0f59ac9ce7e25fbf9ba8f811c96f5ed77d0db1bee9cf', 'resource': md5}
        response = requests.get(url, params=params)
        report = json.loads(response.text)
        for scan in report['scans']:
            #report_scan = json.loads(scan)
            if report['scans'][scan]['detected']:
                return True
        return False




    @staticmethod#waits on receive until http terminal characters are sent
    def receive_all(the_socket):
        message = []
        data = []
        bytes_recv = 0
        message_size = 100000000
        message_size_recvd = False
        try:
            data = the_socket.recv(1024)
            message+=data
            while (bytes_recv < message_size):
                if not message_size_recvd:
                    headers = ''.join(message).splitlines()
                    for header in headers:
                        if "Content-Length" in header or "content-length" in header:
                            message_size = int(header[+15:])
                            message_size_recvd=True
                            break
                data = the_socket.recv(1024)
                #print data
                message+=data
                #bytes_recv+=sys.getsizeof(data)
                p = ''.join(message).find('\r\n\r\n')
                if p:
                    p +=4
                if not p:
                    p = ''.join(message).find('\n\n')
                    p+=2
                if p >=0:
                    bytes_recv = len(message[p:])
        except timeout:
            error_message = "HTTP/1.0 408 Request Timeout\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\nServer: PythonProxy/0.0.1\r\nConnection: Closed\r\n\r\n"
            
        
        body = message[p:]
        return ((''.join(message)),(''.join(body)))

# Represents the server side of the proxy
class server():

    port = 0
    # Starts the server's connection loop
    def start_server(self, port):
        self.port = port
        server_socket = socket(AF_INET,SOCK_STREAM)
        server_socket.bind(('',int(self.port)))
        server_socket.listen(1)
        threads = []
        print "Server listening on port: " + str(self.port)
        while True:
            connection_socket, addr = server_socket.accept()            
            new_thread = ClientThread(connection_socket)#handles request on new thread
            new_thread.start()
            threads.append(new_thread)
            #server.on_connect(connection_socket)
        for t in threads:
            t.join()

    @staticmethod
    def on_connect(the_socket):
        request = server.receive_all(the_socket)#TODO: figure out why all escapes are prepended
        if request is None:
            return
        server.handle_request(the_socket, request)

    @staticmethod#waits on receive until http terminal characters are sent
    def receive_all(the_socket):
        end_http_message_long = '\r\n\r\n'
        end_http_message_short = '\n\n'
        message = ''
        data = ''
        the_socket.settimeout(5)#checks for timeout on request
        try:
            while ((end_http_message_long not in message[-4:]) and (end_http_message_short not in message[-2:])):
                data = the_socket.recv(1024)
                #print data
                message+=data
        except timeout:
            error_message = "HTTP/1.0 408 Request Timeout\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\nServer: PythonProxy/0.0.1\r\nConnection: Closed\r\n\r\n"
            the_socket.sendall(error_message)
            the_socket.close()
            return
                        
        return message
            
    @staticmethod
    def handle_request(connection_socket, request):#handles request once it is parsed
        c = client()
        urldata = server.parse_request(str(request))
        error_occured = urldata[0]

        if error_occured != True:
            hostname = urldata[1]
            port = urldata[2]
            path = urldata[3]
            headers = urldata[4]
            remote_request = "GET " + path + " HTTP/1.0\r\nHost: " + hostname + "\r\nConnection: close\r\n" #GET /~kobus/simple.html \r\nHost: http://www.cs.utah.edu/\r\nConnection:
                                                                                                            #close\r\n\r\n
            for header in headers:                
                remote_request += header + "\r\n"
            remote_request+= "\r\n"
            remote_response = c.make_request(hostname, port, remote_request.encode(encoding='ascii'))

        else:
            remote_response = urldata[1]

        connection_socket.sendall(remote_response)
        connection_socket.close()

    # parses a request to determine the hostname and port (if no port is
    # specified, assumes 80)
    @staticmethod
    def parse_request(request):
        #test_request="GET http://www.cs.utah.edu/~kobus/simple.html
        #HTTP/1.0\r\nHost: www.cs.utah.edu\r\nConnection: close\r\nTest:
        #test1\r\nTest2: test2\r\n\r\n"
        #test_not_implemented="POST http://test.com HTTP/1.0\r\n\r\n"

        error_message = server.determine_error(request)

        if error_message[0] != True:
            find_url = r"(?<=GET\s)\S*(?= HTTP)"
            url = re.findall(find_url, request)   
            
            headers = error_message[1]
            
            url_parser = urlparse(url.pop(0))
            hostname = url_parser.hostname
            port = url_parser.port
            path = url_parser.path
        
            if port is None:
                port = 80
            tup = (False, hostname, port, path, headers)
            return(tup)
        
        
        return error_message
    @staticmethod#determines if request should result in an error
    def determine_error(request):
        has_error = False
        not_implemented = re.match("^(HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)", request)
        if not_implemented:
            error_message = "HTTP/1.0 501 Not Implemented\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\nServer: PythonProxy/0.0.1\r\nConnection: Closed\r\n\r\n"
            has_error = True
        elif re.match("^GET", request) is None:
            error_message = "HTTP/1.0 400 Bad Request\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\nServer: PythonProxy/0.0.1\r\nConnection: Closed\r\n\r\n"
            has_error = True
        else:
            headers = request.splitlines()
            headers.pop(0)
            headers_to_pass = []
            for header in headers:
                if header != "" and header != "\"" and re.match("^\S+:\s\S+", header) is not None:
                    if re.match("^Connection: ", header) is None and re.match("^Host: ", header) is None:
                        headers_to_pass.append(header)
                else:
                    error_message = "HTTP/1.0 400 Bad Request\r\nDate: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\nServer: PythonProxy/0.1.0\r\nConnection: Closed"
                    has_error = True
            has_error = False
            error_message = headers_to_pass

        return(has_error, error_message)


class ClientThread(Thread):#defines a thread for a socket
    client_socket = ""
    def __init__(self, client_socket):
        Thread.__init__(self)
        self.client_socket=client_socket
        
    def run(self):
        server.on_connect(self.client_socket)

#creates and starts a server for the proxy
def main():
    parser = argparse.ArgumentParser(prog='PythonProxy',epilog='Additional Information:\nCurrently some telnet clients prepend all \ with \, causing a double escape. This breaks the parsing of the HTTP request. Normal browsers do not exhibit this behavior\n')

    parser.add_argument("--p", "--port",default=12345, type=int, help="Specifies port to listen on. Default is 12345.")
    args = parser.parse_args()
    port = args.p

    s = server()
    s.start_server(port)


if __name__ == "__main__":
    main()






