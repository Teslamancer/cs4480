from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from socket import *
from optparse import OptionParser

from base64 import b64decode, b64encode
import json
import os

class message():
    message=''
    metadata=''

    def __init__(self, message, metadata="TO_DECODE"):
        if(metadata == "TO_DECODE"):
            self.decode(message)
        else:
            self.message = message
            self.metadata = metadata

    def decode(self, blob):
        obj_dict = json.loads(blob)
        self.message = obj_dict['message']
        self.metadata = obj_dict['metadata']

    def encode(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)

def main():
    parser = OptionParser()

    parser.add_option("-H","--host",dest="bob_address",type="string",default="localhost",help="Specifies hostname/ip address of Bob script. Default is localhost.")
    parser.add_option("-p","--port",dest="port", type="int",default=11111,help="Specifies port to connect to Bob program on. Default is 2100.")
    (options,args) = parser.parse_args()

    connect_to_bob(options.bob_address, options.port)

def verify_message(message_in, key_location):
    data_in = message_in.message
    digest_in = message_in.metadata
    here = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(here, key_location)
    key = RSA.importKey(open(filename).read())
    h = SHA.new(data_in)
    verifier = PKCS1_v1_5.new(key)
    return verifier.verify_message(h, digest_in)



def connect_to_bob(hostname, port):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((hostname,port))    
    request_pubkey = message("REQUEST", "PUBKEY")
    s.sendall(request_pubkey.encode().encode())
    data = receive_blob(s)
    message_in = message(data)
    if(verify_message(message_in)):
        f = open("bobpublickey.pem","x")
        f.write(b64decode(message_in.message).decode())


def receive_blob(the_socket):
    message = ''
    data = ''
    #the_socket.settimeout(5000000)   

    try:
        while('{' not in message[:1]):
            data = the_socket.recv(1024)
            if(data is None):
                continue
            else:
                data = data.decode()
                message+= data
        while('{' in message[:1] and '}' not in message[-1:]):
            data = the_socket.recv(1024).decode()
            message+= data
    except timeout:
        print("Connection timed out!")
        return

    return message

if __name__ == "__main__":
    main()