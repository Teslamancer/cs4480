from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from socket import *
from optparse import OptionParser
import json
from base64 import b64encode, b64decode
import os
import codecs

#the message and metadata are always ascii encoded strings, if a function produces bytes to put in a message,
#it is required to decode them to a ascii string first
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
        message_dict = {}
        message_dict['message'] = self.message
        message_dict['metadata'] = self.metadata
        return json.dumps(message_dict, 
            sort_keys=True, indent=4).encode('utf-8')



def main():
    parser = OptionParser()

    #parser.add_option("-h","--host",dest="bob_address",type="string",default="localhost",help="Specifies hostname/ip address of Bob script. Default is localhost.")
    parser.add_option("-p","--port",dest="port", type="int",default=12345,help="Specifies port to listen for Alice program on. Default is 2100.")
    (options,args) = parser.parse_args()

    # test = message("test message", "test metadata")
    # encoded_test = test.encode()
    # print(encoded_test) 
    # test_receive = message(encoded_test)

    # bob_pubkey = 'test'#file_to_string('bobpublickey.pem')
    # signed_digest = sign_message(bob_pubkey,'caprivatekey.pem')
    # to_send = message(bob_pubkey,signed_digest)
    # print(verify_message(to_send,'capublickey.pem'))

    start_server(options.port)
    

    

def start_server(port):
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(('',int(port)))
    server_socket.listen(1)
    print("Server listening on port: " + str(port))
    connection_socket, addr = server_socket.accept()
    print("Alice connected!")
    while True:
        init_request = receive_blob(connection_socket)
        if(init_request is None):
            continue
        else:
            message_in = message(init_request)
            handle_request(connection_socket, message_in)

def handle_request(the_socket, request):
    if(request.message=="REQUEST" and request.metadata=="PUBKEY"):
        send_pubkey(the_socket)

def send_pubkey(the_socket):
    bob_pubkey = file_to_string('bobpublickey.pem')
    signed_digest = sign_message(bob_pubkey,'caprivatekey.pem')
    to_send = message(bob_pubkey,signed_digest)
    the_socket.sendall(to_send.encode())

def file_to_string(filename):
    here = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(here, filename)
    with open(filename,'r') as file:
        data = file.read()
    
    return data

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

def sign_message(data, key_location):
    here = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(here, key_location)
    key = open(filename,'r').read()
    rsakey = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA.new()

    digest.update(data.encode())

    signature = signer.sign(digest)

    return b64encode(signature).decode('utf-8')

def verify_message(message_in, key_location):
    data_in = message_in.message
    signature = b64decode(message_in.metadata.encode('utf-8'))

    here = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(here, key_location)
    key = RSA.importKey(open(filename).read())
    verifier = PKCS1_v1_5.new(key)
    digest = SHA.new()
    digest.update(data_in.encode())

    
    return verifier.verify(digest, signature)


if __name__ == "__main__":
    main()