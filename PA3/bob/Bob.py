from Crypto.Hash import SHA
from socket import *
from optparse import OptionParser
import json


class message():
    message=''
    metadata=''

    def __init__(self, message, metadata):
        self.message = message
        self.metadata = metadata

    # def __init__(self, encoded_message):
    #     json_message = json.loads()

    def encode(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)



def main():
    parser = OptionParser()

    #parser.add_option("-h","--host",dest="bob_address",type="string",default="localhost",help="Specifies hostname/ip address of Bob script. Default is localhost.")
    parser.add_option("-p","--port",dest="port", type="int",default=2100,help="Specifies port to listen for Alice program on. Default is 2100.")
    (options,args) = parser.parse_args()

    test = message("test message", "test metadata")
    print(test.encode()) 

    

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind('',int(port))
    server_socket.listen(1)
    print("Server listening on port: " + str(port))
    #while True:
    connection_socket, addr = server_socket.accept()
    init_request = connection_socket.receive_blob()


    

    data = receive_blob(server_socket)

def receive_blob(the_socket):
    message = ''
    data = ''
    the_socket.settimeout(5)   

    try:
        while('{' not in message[:1]):
            data = the_socket.recv(1024)
            message+= data
        while('{' in message[:1] and '}' not in message[:-1]):
            data = the_socket.recv(1024)
            message+= data
    except timeout:
        print("Connection timed out!")
        return

    return message




if __name__ == "__main__":
    main()