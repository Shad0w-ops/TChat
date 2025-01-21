##---------------------|--------------------------------------------------------------|
## Authors:            | Shad0w-Ops, UX0l0l                                           |
##---------------------|--------------------------------------------------------------|
## script name:        | TChat Server                                                 |
##---------------------|--------------------------------------------------------------|
## Date of creation:   | 3/9/2023                                                     |
##---------------------|--------------------------------------------------------------|


import socket
import os
import random
import string
import threading
import subprocess
import asyncio
import signal
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Global set to track active nicknames
active_nicknames = set()


def remove_nickname(nickname: str) -> None:
    """Remove a nickname from the active set."""
    if nickname in active_nicknames:
        active_nicknames.remove(nickname)


def clear() -> None:
    subprocess.run("cls" if os.name == "nt" else "clear", shell=True)


def generate_encryption_key() -> str:
    """Generate a secure encryption key using PBKDF2."""
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend(),
    )
    return kdf.derive(os.urandom(64)).hex()


def encrypt_message(message: bytes, key: str) -> bytes:
    """Encrypt message using AES."""
    try:
        cipher = Cipher(
            algorithms.AES(bytes.fromhex(key)),
            modes.CFB(b"\0" * 16),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        return encryptor.update(message)
    except Exception as exc:
        print(f"Encryption error: {exc}")
        return message


def receive_all(sock: socket.socket) -> bytes:
    """Receive entire message from socket, ignoring keepalive packets."""
    chunks = []
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            break
        if chunk == b"\x00":
            continue
        chunks.append(chunk)
        if len(chunk) < 8192:
            break
    return b"".join(chunks)


def handle_client(client_socket: socket.socket, nickname: str, clients: dict) -> None:
    """Handle incoming messages from a specific client."""
    try:
        while True:
            encrypted_message = receive_all(client_socket)
            if not encrypted_message:
                break

            # Format message with nickname prefix
            formatted_message = f"{nickname}: ".encode("utf-8") + encrypted_message
            broadcast(formatted_message, client_socket, clients)

    except BrokenPipeError:
        remove_nickname(nickname)
        if client_socket in clients:
            clients.remove(client_socket)
        clear()
    except (ConnectionError, OSError) as e:
        print(f"Connection error with {nickname}: {e}")
    finally:
        broadcast(
            f"{nickname} left the chat.".encode("utf-8"),
            client_socket,
            clients,
        )
        if client_socket in clients:
            clients.remove(client_socket)
        remove_nickname(nickname)
        client_socket.close()


def broadcast(message: bytes, sender_socket: socket.socket, clients: list) -> None:
    """Send a message to all connected clients including the sender."""
    # First send message length, then the message
    msg_length = len(message).to_bytes(4, "big")

    for client in clients[:]:  # Copy list to avoid modification while iterating
        try:
            client.sendall(msg_length)
            client.sendall(message)
        except BrokenPipeError:
            client.close()
            if client in clients:
                clients.remove(client)
        except (ConnectionError, OSError) as e:
            print(f"Failed to send to client: {e}")
            client.close()
            if client in clients:
                clients.remove(client)


async def handle_connections(
    server: socket.socket,
    password: str,
    clients: list,
    encryption_key: str,
    clients_lock: threading.Lock,
) -> None:
    loop = asyncio.get_event_loop()
    while True:
        try:
            client_socket, client_address = await loop.sock_accept(server)
            client_socket.settimeout(30)

            # Handle each new client in a separate task
            asyncio.create_task(
                handle_new_client(
                    client_socket,
                    client_address,
                    password,
                    clients,
                    encryption_key,
                    clients_lock,
                )
            )

        except (socket.error, ValueError) as e:
            print(f"Connection error: {e}")
            continue


async def handle_new_client(
    client_socket: socket.socket,
    client_address: tuple,
    password: str,
    clients: list,
    encryption_key: str,
    clients_lock: threading.Lock,
) -> None:
    try:
        received_password = receive_all(client_socket).decode("utf-8", errors="ignore")

        if received_password != password:
            client_socket.close()
            return

        client_socket.sendall(f"valid:{encryption_key}".encode("utf-8"))

        # Nickname validation loop
        while True:
            try:
                nickname = (
                    client_socket.recv(1024).decode("utf-8", errors="ignore").strip()
                )

                with clients_lock:
                    if not nickname:
                        client_socket.sendall(b"nickname_taken")
                        continue

                    if nickname not in active_nicknames:
                        active_nicknames.add(nickname)
                        clients.append(client_socket)
                        client_socket.sendall(b"nickname_accepted\n")
                        break
                    else:
                        client_socket.sendall(b"nickname_taken")
            except BrokenPipeError:
                pass
            except Exception as e:
                print(f"Error in nickname validation: {e}")
                return

        # Send join message separately from nickname acceptance
        broadcast(
            f"{nickname} joined the chat.".encode("utf-8"),
            client_socket,
            clients,
        )

        # Handle client messages in a separate thread
        client_thread = threading.Thread(
            target=handle_client, args=(client_socket, nickname, clients)
        )
        client_thread.daemon = True
        client_thread.start()

    except Exception as e:
        print(f"Error handling new client: {e}")
        client_socket.close()


def signal_handler(sig, frame):
    for nickname in active_nicknames.copy():
        remove_nickname(nickname)
    os._exit(0)


async def main():
    clear()
    global active_nicknames

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    clients_lock = threading.Lock()

    host = "0.0.0.0"
    port = 9999
    password = "".join(
        random.SystemRandom().choice(
            string.ascii_letters + string.digits + string.punctuation
        )
        for _ in range(16)
    )
    encryption_key = generate_encryption_key()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)
    server.setblocking(False)

    print(f"[*] Password for server is: {password}")

    print(f"[*] Server is listening on {host}:{port}")

    clients = []
    try:
        await handle_connections(
            server, password, clients, encryption_key, clients_lock
        )
    except KeyboardInterrupt:
        for client in clients:
            try:
                client.sendall(b"Server shutting down...")
                client.close()
            except Exception:
                pass
    except Exception as e:
        print(f"Fatal error: {e}")
    finally:
        for client in clients:
            try:
                client.close()
            except Exception:
                pass
        server.close()


if __name__ == "__main__":
    asyncio.run(main())
