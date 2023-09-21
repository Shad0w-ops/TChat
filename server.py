##---------------------|--------------------------------------------------------------|
## Author:             | Shad0w-Ops                                                   |
##---------------------|--------------------------------------------------------------|
## script name:        | Tchat Server                                                 |
##---------------------|--------------------------------------------------------------|
## Date of creation:   | 3/9/2023                                                     |
##---------------------|--------------------------------------------------------------|
## purpose:            | A simple yet effective terminal based chatting script        |
##                     | made with integrated portforwarding using ngrok and          |
##                     | end-to-end encryption using the fernet encryption algorythm. | 
##---------------------|--------------------------------------------------------------|
## Tested on:          | Kali Linux  : Terminator                                     |
##---------------------|--------------------------------------------------------------|

#importing libraries
import socket
import threading
import os
from pyngrok import ngrok
import random
import string
from termcolor import colored
from cryptography.fernet import Fernet

# Constants
BANNER = '''
  ______     __          __     _____                          
 /_  __/____/ /_  ____ _/ /_   / ___/___  ______   _____  _____
  / / / ___/ __ \/ __ `/ __/   \__ \/ _ \/ ___/ | / / _ \/ ___/
 / / / /__/ / / / /_/ / /_    ___/ /  __/ /   | |/ /  __/ /    
/_/  \___/_/ /_/\__,_/\__/   /____/\___/_/    |___/\___/_/     
--------------------------v1.1---------------------------   
                                                       
'''

#-----------------------Defining Functions-------------------------#

# Function to generate a secure random password
def generate_password():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(10)) #generates a 10 character random password

# Function to generate a Fernet key
def generate_fernet_key():
    return Fernet.generate_key().decode()

# Function to generate a random port number
def generate_portnumber():
    return str(random.randint(1024, 65535))

# Function to start Ngrok and expose the server
def start_ngrok(port):
    ngrok_tunnel = ngrok.connect(port, "tcp")
    
    starts = "[*] Server has been initiated."
    print(colored(starts, 'green'))

    print(f"\033[92m[*] Ngrok tunnel URL: {ngrok_tunnel.public_url}\033[0m")

# Function to handle client connections
def handle_client(client_socket, nickname):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8') # Decode UTF-8 encoded incoming messages
            if not message:
                break
            print(f"{nickname}: {message}")
            broadcast(f"{nickname}: {message}", client_socket)
        except Exception as e:
            print(f"An error occurred while handling client: {str(e)}")
            break
    print(colored(f"{nickname} left the chat", 'red'))  # Print when a client leaves
    broadcast(colored(f"{nickname} left the chat", 'red'), client_socket)  # Broadcast when a client leaves

# Function to broadcast messages to all clients
def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message.encode('utf-8')) # UTF-8 encode before broadcasting messages to clients
            except Exception as e:
                print(f"An error occurred while broadcasting: {str(e)}")
                client.close()
                clients.remove(client)

#----------------------Server-Initialization-----------------------#

if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(generate_portnumber())

    characters = string.printable
    password = generate_password()
    fernet_key = generate_fernet_key()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    os.system("clear")
    print(colored(BANNER, 'red'))

    start_ngrok(port)

    passwd = "[*] Password for server is: " + password
    print(colored(passwd, 'green'))

    print(colored(f"[*] Fernet Key: {fernet_key}", 'green'))

    message = f"[*] Server is listening on {host}:{port}"
    message_length = len(message)
    print(colored(message, 'green'))
    print("=" * message_length)

    clients = []

    try:
        while True:
            client_socket, client_address = server.accept()
            ack = f"[*] Accepted connection from {client_address[0]}:{client_address[1]}"
            print(colored(ack, 'green'))

            received_password = client_socket.recv(1024).decode('utf-8')

            if received_password != password:
                print(f"Invalid password from {client_address[0]}:{client_address[1]}")
                client_socket.close()
            else:
                client_socket.send("valid".encode('utf-8'))

                nickname = client_socket.recv(1024).decode('utf-8')
                clients.append(client_socket)

                print(f"Nickname for {client_address[0]}:{client_address[1]} is {nickname}")

                colored_message = f"{nickname} joined the chat."
                broadcast(colored_message, client_socket)

                client_thread = threading.Thread(target=handle_client, args=(client_socket, nickname))
                client_thread.start()
    except KeyboardInterrupt:
        print(colored("Server Terminated", 'red'))
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        for client in clients:
            client.close()
        server.close()