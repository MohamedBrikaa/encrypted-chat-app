import socket
from threading import Thread
import sys
# import select 


IP = "127.0.0.1"
PORT = 1234
BUFSIZ = 1024

server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#Not Necessary
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 

server_socket.bind((IP,PORT))
print( "server done binding to host and port successfully")
print("server is waiting for incoming connections")

server_socket.listen()
# list_of_clients = [] 
client_socket, client_address = server_socket.accept() 
# list_of_clients.append(client_socket)


def handle_client(client_socket, client_address):
    print("new thread to handle the client")
    while True: 
        try: 
            message = client_socket.recv(2048).decode("utf8")
            if message: 
                print ("client>>" + message)  
        except: 
            continue

def wait_to_send_messages():
    while True:
        sent_mssg= input()
        print ("server>>" + sent_mssg)
        print("clear")  
        client_socket.send(bytes(sent_mssg, "utf8"))

#/////////////////////////////////////////////////
print("%s:%s has connected." % client_address)
print("send welcome mssg and ask for client public key")
client_socket.send(bytes("Greetings from the Server! please send your public key", "utf8") )
client_public_key = client_socket.recv(BUFSIZ).decode("utf8")
print("client public key recwived: "+ client_public_key)

print("send server public key")
client_socket.send(bytes("server public key", "utf8"))
Thread(target=handle_client, args=(client_socket,client_address)).start()
wait_to_send_messages()

#/////////////////////////////////////////////////
   