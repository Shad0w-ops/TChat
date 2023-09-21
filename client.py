##---------------------|--------------------------------------------------------------|
## Author:             | Shad0w-Ops                                                   |
##---------------------|--------------------------------------------------------------|
## script name:        | Tchat Client                                                 |
##---------------------|--------------------------------------------------------------|
## Date of creation:   | 3/9/2023                                                     |
##---------------------|--------------------------------------------------------------|
## purpose:            | A simple yet effective terminal based chatting script        |
##                     | made with integrated portforwarding using ngrok and          |
##                     | end-to-end encryption using the fernet encryption algorythm. | 
##---------------------|--------------------------------------------------------------|
## Tested on:          | Kali Linux  : Terminator                                     |
##---------------------|--------------------------------------------------------------|

# Importing Libraries
import socket
import threading
import os
from termcolor import colored
from cryptography.fernet import Fernet
import re
import datetime
import socks
import socket


#-------------------------Defining-Class---------------------------#

class ChatClient:
    def __init__(self):
        self.BANNER = '''
  ______________          __     _________            __ 
 /_  __/ ____/ /_  ____ _/ /_   / ____/ (_)__  ____  / /_
  / / / /   / __ \/ __ `/ __/  / /   / / / _ \/ __ \/ __/
 / / / /___/ / / / /_/ / /_   / /___/ / /  __/ / / / /_  
/_/  \____/_/ /_/\__,_/\__/   \____/_/_/\___/_/ /_/\__/  
--------------------------v1.1---------------------------                                                        
'''
        self.fernet_key = None     #Encryption Key Holder
        self.client_socket = None  #Socket Connection
        self.nickname = None       # User Identifier


#-----------------------Defining Functions-------------------------#


    def input_fernet_key(self):   # User Fernet key input
        try:
            key = input("Enter your Fernet key: ")
            self.fernet_key = Fernet(key)
            print(colored("Fernet key set.", 'cyan'))
        except Exception as e:
            print(colored(f"Error setting Fernet key: {str(e)}", 'red'))

#------------------------------------------------------------------#

    def receive_messages(self):   # Function to Handle recieved messages
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)  #Recieve Message
                if not encrypted_message:
                    print(colored("Connection closed.", 'red'))    # Closes connection if server went offline
                    break
                if b'left' in encrypted_message:                   # if message was recieved containing the plaintext word "left"
                    left = encrypted_message.decode('utf-8')       # it would print it out without sending it to be decrypted
                    print(colored("\n"+left, 'red'))
                    continue

                if self.fernet_key:
                    try:
                        message_str = encrypted_message.decode('utf-8')     # UTF-8 decode inoming messages
                        matches = re.findall(r'gAA[^:]+=', message_str)     # Regex to search for base64 encoded string

                        if matches:                                         # if base64 encoded string was found, it will be sent to be Fernet decrypted
                            for match in matches:
                                decrypted_message = self.fernet_key.decrypt(match.encode('utf-8')).decode('utf-8')
                                parts = encrypted_message.decode('utf-8').split(':', 1) # split the encrypted text to 2 parts (user:message)
                                if len(parts) == 2:
                                    user = parts[0]     # User nickname saved to variable (User)
                                    message = parts[1]  # Message saved to variable message

                                    timestamp = datetime.datetime.now().strftime('%H:%M:%S')             # Prints time stamps next to recieved messages
                                    print(f"\n\033[92m[{timestamp}] {user}: {decrypted_message}\033[0m") # Prints user: decrypted message
                                else:
                                    print(f"unknown: {decrypted_message}")                               # If user nickname not found print(unknown: decrypted message)
                        else:
                            message = str(encrypted_message)[2:-1]
                            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                            print(f"\n\033[92m[{timestamp}] {message}\033[0m")                           # If base64 encoded text is not found, the script will print out exactly what it recieved


                    #------------------------Error-Handeling---------------------------#

                    except Exception as decrypt_error:
                        print(colored(f"Error decrypting message: {str(decrypt_error)}", 'red'))
                else:
                    print(colored("No Fernet key set. Cannot decrypt message.", 'yellow'))
                print("you: ", end="", flush=True)
            except Exception as receive_error:
                print(f"An error occurred while receiving messages: {str(receive_error)}")
                break
#------------------------------------------------------------------#
    def send_messages(self):    # Function to handle sending messages
        while True:
            try:
                timestamp = datetime.datetime.now().strftime('%H:%M:%S')    # Prints time stamps next to sent messages
                print(f"{timestamp} you: ", end="", flush=True)                         #indication of where the user input is indicated by (You: )
                message = input()
                if self.fernet_key:
                    encrypted_message = self.fernet_key.encrypt(message.encode('utf-8'))    # Encrypt messages using Fernet before sending them
                    self.client_socket.send(encrypted_message)

#------------------------Error-Handeling---------------------------#

                else:
                    print(colored("No Fernet key set. Cannot send message.", 'yellow'))
            except KeyboardInterrupt:
                print(colored("\nClient Terminated", 'red'))
                self.client_socket.close()
                break
            except Exception as e:
                print(f"An error occurred while sending messages: {str(e)}")

#------------------------------------------------------------------#

    def start(self):
        os.system("clear")
        print(f"\033[91m{self.BANNER}\033[0m")
        
        try:
            address_input = input("Enter the server address (address:port): ")
        except KeyboardInterrupt:
            print(colored("Client Terminated", 'red'))
            exit()

        address_parts = address_input.split(':')
        if len(address_parts) != 2:
            print("Invalid address format. Please provide in the format 'hostname:port'.")
        else:
            host = address_parts[0]
            port = int(address_parts[1])

            try:
                password = input("Enter the server password: ")
            except KeyboardInterrupt:
                print(colored("Client Terminated", 'red'))
                self.client_socket.close()
                exit()

            self.client_socket = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.set_proxy(socks.SOCKS5, '127.0.0.1', 9050)  # Set Tor SOCKS proxy
            self.client_socket.connect((host, port))

            os.system("clear")
            print(f"\033[91m{self.BANNER}\033[0m")

            self.client_socket.send(password.encode('utf-8'))
            password_ack = self.client_socket.recv(1024).decode('utf-8')

            if password_ack == "valid":
                try:
                    self.nickname = input("Access Granted. \nPlease enter your nickname: ")
                except KeyboardInterrupt:
                    print(colored("Client Terminated", 'red'))
                    self.client_socket.close()
                    exit()

                self.input_fernet_key()

                os.system("clear")

                print(f"\033[91m{self.BANNER}\033[0m")
                ack = self.nickname + " joined the chat."
                print(f"\033[92m{ack}\033[0m")

                print("-------------------------")

                receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
                send_thread = threading.Thread(target=self.send_messages, daemon=True)

                receive_thread.start()
                send_thread.start()

                try:
                    send_thread.join()
                except KeyboardInterrupt:
                    print(colored("Client Terminated", 'red'))
                    self.client_socket.close()

if __name__ == "__main__":
    chat_client = ChatClient()
    chat_client.start()
