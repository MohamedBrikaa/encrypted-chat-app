import socket
from threading import Thread
import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import time


# generate RSA and AES Keys
key = RSA.generate(1024)
my_private_key = key.export_key()
my_public_key = key.publickey().export_key()
ra_session_key = get_random_bytes(16)


IP = "127.0.0.1"
PORT = 1234
BUFSIZ = 1024

server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.connect((IP, PORT)) 
print("Connected to chat server")

# *****************Function definitions****************

#Function to listen for server messages 
def listen_for_server_mssg():
        while True: 
            try:
                #receive decryption parametrs
                message = receive_encrypted_message()
                if message: 
                    print ("server>>" + message.decode("utf-8"))  
            except: 
                continue
            
#Function to send client messages 
def wait_to_send_messages():
    while True:
        sent_mssg= input()
        # Encrypt the data with the AES session key
        cipher_aes = AES.new(ra_session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(sent_mssg.encode("utf-8"))
        #send encryption parametrs
        server_socket.send(ciphertext)
        time.sleep(.1)
        server_socket.send(tag)
        time.sleep(.1)
        server_socket.send(cipher_aes.nonce)
        print ("client>>" + sent_mssg)

def receive_encrypted_message():
    #receive decryption parametrs
    ciphertext = server_socket.recv(BUFSIZ)
    tag = server_socket.recv(BUFSIZ)
    nonce = server_socket.recv(BUFSIZ)
    #decrypt message 
    message = aes_decrypt(ra_session_key,nonce,ciphertext,tag)
    return message

def aes_decrypt(session_key,nonce,ciphertext,tag):
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return message
#***************************************************

# *****************Public key Sharing*****************
# send and receive public keys with server to encrypt session key
welcome_message=server_socket.recv(BUFSIZ).decode("utf8")
print(welcome_message)
server_socket.send(my_public_key)
print("client public key sent")
server_public_key = RSA.import_key(server_socket.recv(BUFSIZ).decode("utf8"))
print("server public key received : "+ str(server_public_key))
#***************************************************

# *****************Session key Sharing*****************
#share session key (RA)
print("session key before encryption:" + str(ra_session_key))
cipher_rsa = PKCS1_OAEP.new(server_public_key)
enc_session_key = cipher_rsa.encrypt(ra_session_key)
server_socket.send(enc_session_key)
print("session key after encryption:" + str(enc_session_key))
#***************************************************

# ***************** start chating *****************
Thread(target=listen_for_server_mssg).start()
wait_to_send_messages()
