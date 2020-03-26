import socket
from threading import Thread
import sys


IP = "127.0.0.1"
PORT = 1234
BUFSIZ = 1024

server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.connect((IP, PORT)) 
print("Connected to chat server")

def listen_for_server_mssg():
    print("new thread to listen for client mssg")
    while True: 
        incoming_message=server_socket.recv(BUFSIZ).decode("utf8")
        print("server>>"+incoming_message)

def wait_to_send_messages():
    while True:
        sent_mssg= input()
        print ("client>>" + sent_mssg)  
        server_socket.send(bytes(sent_mssg, "utf8") )

welcome_message=server_socket.recv(BUFSIZ).decode("utf8")
print(welcome_message)

server_socket.send(bytes("client public key", "utf8"))
print("client public key sent")

server_public_key = server_socket.recv(BUFSIZ).decode("utf8")
print("server public key received : "+ server_public_key)
Thread(target=listen_for_server_mssg).start()
wait_to_send_messages()
