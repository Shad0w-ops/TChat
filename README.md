# Tchat Server and Client

![Screenshot_2023-09-06_08-00-53](https://github.com/Shad0w-ops/TChat/assets/43708460/2113c837-bf01-4b07-8aef-ab4bbc443ade)

Tchat is a simple yet effective terminal-based chatting script made with integrated port forwarding using ngrok and end-to-end encryption using the Fernet encryption algorithm.

## Features

- Terminal-based chat server and client.
- Integrated port forwarding using ngrok for easy external access.
- End-to-end encryption using the Fernet encryption algorithm.
- Password protection for server access.
- User-friendly and customizable.

## Installation


  Clone the repository:
  
    git clone https://github.com/yourusername/tchat.git
   
  Navigate to the TChat directory:
  
    cd tchat/server

  Install the requirements:
  
    pip3 install -r requirements.txt

## Usage

  First you need to start the TChat server:
  ```bash
  python3 server.py
  ```
  
![Screenshot_2023-09-06_07-07-43](https://github.com/Shad0w-ops/TChat/assets/43708460/f49f4df9-dfd3-4434-a156-7512e9c62a87)

This will generate a random ngrok address, local port, password and fernet secret key.

now you and your friends are ready to start chatting :)

on a different terminal, run the client script.

![Screenshot_2023-09-06_07-42-51](https://github.com/Shad0w-ops/TChat/assets/43708460/49acf8e2-2bf8-478c-9db6-d2c644f132b9)

it will ask you for the server address and port, make sure to use it without tcp://
then paste the server password.

it will then ask you for a nickname and the fernet key

for the nickname you can use any name/alias that you want to go by in that chat

for the fernet key, make sure to copy and paste it from the server and inclue the "=" in the end example "uwvOTbNmHofe1vA41Qlox3lbNgL0qFlFyhaAAAaSi6o="

and now you are ready to chat with your friends, just give them the credentials from the server but make sure to send it to them in a secure manner.

Enjoy chatting 😊

  
