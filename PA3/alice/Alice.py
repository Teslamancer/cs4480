from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3
from Crypto import Random

from socket import *
from optparse import OptionParser

from base64 import b64decode, b64encode
import json
import os
import codecs

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

verbose = True

def main():
    parser = OptionParser()

    parser.add_option("-H","--host",dest="bob_address",type="string",default="localhost",help="Specifies hostname/ip address of Bob script. Default is localhost.")
    parser.add_option("-p","--port",dest="port", type="int",default=4480,help="Specifies port to connect to Bob program on. Default is 4480.")
    parser.add_option("-m","--message",dest="message", type="string",default="Test Message",help="Message to encrypt and send to Bob. Default is 'Test Message'.")
    parser.add_option("-q","--quiet",dest="quiet", default=False,help="Suppresses console reporting of progress.")
    (options,args) = parser.parse_args()
    verbose = not options.quiet
    #connect to bob program and request Bob's public key to write to file
    if(verbose):
        print("Connecting to Bob")
    bob_socket = connect_to_bob(options.bob_address, options.port)
    if(verbose):
        print("Requesting Public Key from Bob")
    bob_key = request_pubkey(bob_socket)
    if(verbose):
        print("Bob Public Key Received:")
        print(bob_key)


    #sign input message hash with Alice's private Key and store with message in a message object
    if(verbose):
        print("Input Message was:")
        print(options.message)
    message_signature = sign_message(options.message, "aliceprivatekey.pem")
    if(verbose):
        print("Signing Message Hash with Private Key")
    message_and_signature = message(options.message, message_signature)
    if(verbose):
        print("Hashed Signature Digest:")
        print(message_signature)

    #generate DES3 key and iv, place into a message to hold key and iv
    if(verbose):
        print("Generating DES3 Key")
    (key, iv) = gen_des3_params()#key, iv are bytes
    if(verbose):
        print("Key Values:")
        print("key: " + key.decode('hex'))
        print("iv: " + iv.decode('hex'))
    sym_key = message(b64encode(key).decode('utf-8'),b64encode(iv).decode('utf-8'))
    #encrypt JSON of message + signature with DES3 key and iv
    if(verbose):
        print("Encrypting Message+Hash with Symmetric Key")
    encrypted_message = des3_encrypt(key, iv, message_and_signature.encode())

    #encrypt DES3 key and iv message with Bob's public key
    if(verbose):
        print("Encrypting Symmetric Key with Bob's Public Key")
    rsa_encrypted_key = rsa_encrypt(sym_key.encode(),'bobpublickey.pem')
    if(verbose):
        print("Encrypted Key: " + rsa_encrypted_key)

    if(verbose):
        print("Sending data to Bob")

    message_to_send = message(encrypted_message,rsa_encrypted_key)

    bob_socket.sendall(message_to_send.encode())
    if(verbose):
        print("Data Sent")

    # rsa_decrypted_key = rsa_decrypt(rsa_encrypted_key, 'aliceprivatekey.pem')

    # decrypted_key_message = message(rsa_decrypted_key)

    # print(sym_key.message == decrypted_key_message.message)
    # print(sym_key.metadata == decrypted_key_message.metadata)

    #decrypted_message = des3_decrypt(key, iv, encrypted_message)

def rsa_encrypt(data, key_location):
    here = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(here, key_location)

    key = RSA.importKey(open(filename).read())
    cipher = PKCS1_OAEP.new(key)

    ciphertext = cipher.encrypt(data)

    return b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(data, key_location):
    here = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(here, key_location)

    ciphertext = b64decode(data.encode('utf-8'))

    key = RSA.importKey(open(filename).read())
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext.decode('utf-8')

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

def gen_des3_params():
    key = Random.get_random_bytes(16)
    iv = Random.new().read(DES3.block_size)#DES3.block_size == 8
    return (key, iv)

def des3_encrypt(key, iv, data):
    b64_data = b64encode(data).decode('utf-8')
    encryptor = DES3.new(key, DES3.MODE_CBC, iv)
    pad_len = 8 - len(b64_data) % 8 # length of padding
    padding = chr(pad_len) * pad_len # PKCS5 padding content
    b64_data += padding
    return b64encode(encryptor.encrypt(b64_data)).decode('utf-8')


def des3_decrypt(key, iv, data):
    unencode_data = b64decode(data.encode('utf-8'))
    encryptor = DES3.new(key, DES3.MODE_CBC, iv)
    result = encryptor.decrypt(unencode_data)
    pad_len = ord(result[-1:])
    result = result[:-pad_len]
    return b64decode(result.decode('utf-8')).decode('utf-8')



def connect_to_bob(hostname, port):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((hostname,port))   
    print("Connected to Bob")
    return s 
    
def request_pubkey(the_socket):
    request_pubkey = message("REQUEST", "PUBKEY")
    the_socket.sendall(request_pubkey.encode())
    data = receive_blob(the_socket)
    message_in = message(data)
    if(verbose):
        print("Verifying Bob's Public Key")
    if(verify_message(message_in, "capublickey.pem")):
        if(verbose):
            print("Verified! Saving to bobpublickey.pem")
        here = os.path.dirname(os.path.abspath(__file__))
        filename = os.path.join(here, "bobpublickey.pem")
        f = open(filename,"x")
        f.write(message_in.message)
        print("Bob Public Key Received and Verified")
        return message_in.message


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