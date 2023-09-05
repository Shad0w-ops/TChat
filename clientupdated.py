import socket
import threading
import os
from termcolor import colored
from cryptography.fernet import Fernet
import re
import datetime

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
        self.fernet_key = None
        self.client_socket = None
        self.nickname = None

    def input_fernet_key(self):
        try:
            key = input("Enter your Fernet key: ")
            self.fernet_key = Fernet(key)
            print(colored("Fernet key set.", 'cyan'))
        except Exception as e:
            print(colored(f"Error setting Fernet key: {str(e)}", 'red'))

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    print(colored("Connection closed.", 'red'))
                    break
                if b'left' in encrypted_message:
                    left = encrypted_message.decode('utf-8')
                    print(colored(left, 'red'))
                    continue

                if self.fernet_key:
                    try:
                        message_str = encrypted_message.decode('utf-8')
                        matches = re.findall(r'gAA[^:]+=', message_str)

                        if matches:
                            for match in matches:
                                decrypted_message = self.fernet_key.decrypt(match.encode('utf-8')).decode('utf-8')
                                parts = encrypted_message.decode('utf-8').split(':', 1)
                                if len(parts) == 2:
                                    user = parts[0]
                                    message = parts[1]
                                    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                                    print(f"\n\033[92m[{timestamp}] {user}: {decrypted_message}\033[0m")
                                else:
                                    print(f"unknown: {decrypted_message}")
                        else:
                            message = str(encrypted_message)[2:-1]
                            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                            print(f"\n\033[92m[{timestamp}] {message}\033[0m")

                    except Exception as decrypt_error:
                        print(colored(f"Error decrypting message: {str(decrypt_error)}", 'red'))
                else:
                    print(colored("No Fernet key set. Cannot decrypt message.", 'yellow'))
                print("you: ", end="", flush=True)
            except Exception as receive_error:
                print(f"An error occurred while receiving messages: {str(receive_error)}")
                break

    def send_messages(self):
        while True:
            try:
                timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                print("you: ", end="", flush=True)
                message = input()
                if self.fernet_key:
                    encrypted_message = self.fernet_key.encrypt(message.encode('utf-8'))
                    self.client_socket.send(encrypted_message)
                else:
                    print(colored("No Fernet key set. Cannot send message.", 'yellow'))
            except KeyboardInterrupt:
                print(colored("\nClient Terminated", 'red'))
                self.client_socket.close()
                break
            except Exception as e:
                print(f"An error occurred while sending messages: {str(e)}")

    def start(self):
        os.system("clear")
        print(f"\033[91m{self.BANNER}\033[0m")

        try:
            address_input = input("Enter the server address: ")
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
                exit()

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))

            os.system("clear")
            print(f"\033[91m{self.BANNER}\033[0m")

            self.client_socket.send(password.encode('utf-8'))
            password_ack = self.client_socket.recv(1024).decode('utf-8')

            if password_ack == "valid":
                try:
                    self.nickname = input("Password accepted. \nPlease enter your nickname: ")
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

                self.client_socket.send(self.nickname.encode('utf-8'))

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
