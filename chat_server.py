import socket
from threading import Thread
import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import time



key = RSA.generate(1024)
my_private_key = key.export_key()
my_public_key = key.publickey().export_key()
ra_session_key=""

IP = "127.0.0.1"
PORT = 1234
BUFSIZ = 1024

server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#Not Necessary
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 

# *****************accept connection*****************
server_socket.bind((IP,PORT))
print( "server done binding to host and port successfully")
print("server is waiting for incoming connections")
server_socket.listen()
client_socket, client_address = server_socket.accept() 
print("%s:%s has connected." % client_address)
#***************************************************

# *****************Function definitions*****************
def handle_client(client_socket, client_address):
    print("new thread to handle the client")
    while True: 
        try:
            #receive decryption parametrs
            message = receive_encrypted_message()
            if message: 
                print ("client>>" + message.decode("utf-8"))  
        except: 
            continue

def wait_to_send_messages():
    print("function to send server message")
    while True:
        sent_mssg= input()
        # Encrypt the data with the AES session key
        cipher_aes = AES.new(ra_session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(sent_mssg.encode("utf-8"))
        #send encryption parametrs
        client_socket.send(ciphertext)
        time.sleep(.1)
        client_socket.send(tag)
        time.sleep(.1)
        client_socket.send(cipher_aes.nonce)
        print ("server>>" + sent_mssg)

def receive_encrypted_message():
    #receive decryption parametrs
    ciphertext = client_socket.recv(BUFSIZ)
    tag = client_socket.recv(BUFSIZ)
    nonce = client_socket.recv(BUFSIZ)
    #decrypt message 
    message = aes_decrypt(ra_session_key,nonce,ciphertext,tag)
    return message

def aes_decrypt(session_key,nonce,ciphertext,tag):
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return message
#***************************************************

# *****************Public key Sharing*****************
# send and receive public keys with client to encrypt session key
client_socket.send(bytes("Greetings from the Server! please send your public key", "utf8") )
client_public_key =  client_socket.recv(BUFSIZ).decode("utf8")
print("client public key received: "+ client_public_key)
print("send server public key")
client_socket.send(my_public_key)
#***************************************************

# *****************Session key Sharing*****************
#get session key (RA)
enc_session_key = client_socket.recv(BUFSIZ)
print("session key before decryption:" + str(enc_session_key))
cipher_rsa = PKCS1_OAEP.new(key)
ra_session_key = cipher_rsa.decrypt(enc_session_key)
print("session key after decryption:" + str(ra_session_key))
#***************************************************

# ***************** start chating *****************
Thread(target=handle_client, args=(client_socket,client_address)).start()
wait_to_send_messages()

   