![Screenshot_2023-09-06_08-00-53](https://github.com/Shad0w-ops/TChat/assets/43708460/2113c837-bf01-4b07-8aef-ab4bbc443ade)

# TChat Server and Client

**TChat** is a simple TUI chat client (and server) with end-to-end encryption using AES-SHA512 and automatically routes the traffic through tor for increased anonymity and security.

## Features

- Terminal-based chat server and client.
- ~~Integrated port forwarding using ngrok for easy external access.~~
- Automatically routes traffic through tor for increased anonymity and security.
- End-to-end encryption using the AES-SHA512.
- Password protection for server access.
- User-friendly and customizable.
- Vim motions while in the message area (you can enter it by pressing "escape").

## TODO

- [ ] Automatically-generate onion links for external access and increased security (using stem or another tor library).
- [ ] Add support for more vim functionality (e.g. search, yank, etc).
- [ ] Add a WebUI implementation.

## Installation

Clone the repository:
```bash
git clone https://github.com/Shad0w-ops/TChat.git
```

Navigate to the TChat directory:
```bash
cd TChat
```

Install the requirements (we recommend using uv for easy python package management):
```bash
uv sync
```

You can still install dependencies normally using pip:
```bash
pip install -r requirements.txt
```

## Usage

First you need to start the TChat server (using uv):
```bash
uv run server.py
```

or with python:

```bash
python server.py
```

In a different terminal, run the client script (using uv).

```bash
uv run client.py
```

or with python:

```bash
python client.py
```

It will ask you for the server address, then for the server password.

You will then be prompted to enter your chosen nickname.

Enjoy chatting 😊
