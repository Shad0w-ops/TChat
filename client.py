##---------------------|--------------------------------------------------------------|
## Authors:            | Shad0w-Ops, UX0l0l                                           |
##---------------------|--------------------------------------------------------------|
## script name:        | TChat Client                                                 |
##---------------------|--------------------------------------------------------------|
## Date of creation:   | 3/9/2023                                                     |
##---------------------|--------------------------------------------------------------|


import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import datetime
import subprocess
import threading
import socks
from prompt_toolkit import Application
from prompt_toolkit.layout import Layout, HSplit, ScrollablePane
from prompt_toolkit.widgets import TextArea
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.shortcuts import input_dialog, message_dialog, yes_no_dialog
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.key_binding.vi_state import InputMode


def clear() -> None:
    """Clear terminal screen"""
    subprocess.run("cls" if os.name == "nt" else "clear", shell=True, check=True)


def decrypt_message(
    encrypted_message: bytes, key: bytes, iv: bytes = b"\0" * 16
) -> str:
    """Decrypt message with authentication"""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    result = decryptor.update(encrypted_message) + decryptor.finalize()
    return result.decode("utf-8", errors="replace")


def send_keepalive(client_socket: socket.socket) -> None:
    """Send periodic keepalive pings"""
    while True:
        try:
            client_socket.sendall(b"\x00")  # Send null byte as keepalive
            threading.Event().wait(5)
        except BrokenPipeError:
            pass


def receive_messages(
    client_socket: socket.socket, key: bytes, message_area: TextArea, nickname: str
) -> None:
    """Handle incoming messages with improved security"""
    message_area.text = ""  # Initialize with empty string instead of None
    while True:
        # First receive message length
        length_data = client_socket.recv(4)
        if not length_data:
            message_area.text = "<red>Connection closed.</red>"
            break

        msg_length = int.from_bytes(length_data, "big")

        # Receive message in chunks
        chunks = []
        bytes_received = 0
        while bytes_received < msg_length:
            chunk = client_socket.recv(min(msg_length - bytes_received, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_received += len(chunk)

        message = b"".join(chunks)

        # Handle system messages
        if b"left" in message or b"joined" in message:
            system_msg = message.decode("utf-8")
            if message_area.text:
                message_area.text += f"\n{system_msg}"
            else:
                message_area.text = system_msg
            continue

        header_end = message.index(b": ") + 2
        header = message[:header_end].decode("utf-8")
        message_content = message[header_end:]

        if key:
            decrypted_content = decrypt_message(message_content, key)
            if decrypted_content:
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                sender = header.split(":")[0]
                you_tag = " (You)" if sender == nickname else ""
                formatted_msg = f"[{timestamp}]{you_tag} {header}{decrypted_content}"
                if message_area.text:
                    message_area.text += f"\n{formatted_msg}"
                else:
                    message_area.text = formatted_msg
        else:
            if message_area.text:
                message_area.text += "\nNo encryption key set."
            else:
                message_area.text = "No encryption key set."


def encrypt_message(message: str, key: bytes, iv: bytes = b"\0" * 16) -> bytes:
    """Encrypt message with improved security"""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode("utf-8")) + encryptor.finalize()


def send_messages(
    client_socket: socket.socket, key: bytes, input_area: TextArea
) -> None:
    """Handle sending messages securely"""

    def accept_text(buff):
        message = input_area.text.strip()
        if not message:
            return

        if key:
            encrypted_message = encrypt_message(message, key)
            if encrypted_message:
                client_socket.sendall(encrypted_message)
                input_area.text = ""
        else:
            input_area.text = "No encryption key set."

    return accept_text


def handle_chat(client_socket: socket.socket, key: bytes, nickname: str) -> None:
    """Handle chat operations securely"""
    message_area = TextArea(focusable=True, read_only=True)
    input_area = TextArea(height=1, prompt="You: ")

    kb = KeyBindings()

    layout = Layout(
        ScrollablePane(
            HSplit(
                [
                    message_area,
                    input_area,
                ]
            )
        )
    )

    @kb.add("escape")
    def _(event):
        """Enable Vim mode on Escape."""
        if layout.has_focus(input_area):
            layout.focus(message_area)
            event.app.vi_state.input_mode = InputMode.NAVIGATION

    @kb.add("enter")
    def _(event):
        buff = event.app.current_buffer
        send_messages(client_socket, key, input_area)(buff)

    @kb.add("c-c")
    def _(event):
        """Exit the application."""
        event.app.exit()

    app = Application(
        layout=layout,
        key_bindings=kb,
        full_screen=True,
        editing_mode=EditingMode.VI,
    )

    layout.focus(input_area)

    keepalive_thread = threading.Thread(
        target=send_keepalive, args=(client_socket,), daemon=True
    )
    receive_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket, key, message_area, nickname),
        daemon=True,
    )

    keepalive_thread.start()
    receive_thread.start()

    app.run()


def main():
    """Start the TChat client with improved security"""
    clear()

    host = input_dialog(
        title="Server Connection",
        text="Enter the server hostname/address:",
        default="127.0.0.1",
    ).run()

    if not host:
        host = "127.0.0.1"

    if host in ["localhost", "127.0.0.1"] or host.startswith("192.168."):
        proceed = message_dialog(
            title="Local Connection",
            text="This appears to be a local connection, therefore Tor is disabled by default.",
        ).run()

        if not proceed:
            message_dialog(
                title="Cancelled", text="Connection cancelled by user."
            ).run()
            return

    proceed = yes_no_dialog(
        title="Tor Connection",
        text="Tor is enabled by default for non-local connections. Do you wish to proceed with connecting through Tor?",
    ).run()

    password = input_dialog(
        title="Server Password", text="Enter the server password:", password=True
    ).run()

    if not password:
        message_dialog(title="Error", text="Invalid password").run()
        return

    # Configure socket based on connection type
    if host not in ["localhost", "127.0.0.1"] and not host.startswith("192.168."):
        try:
            client_socket = socks.socksocket()
            client_socket.set_proxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
        except socks.ProxyConnectionError:
            message_dialog(
                title="Tor Error",
                text="Could not connect to Tor proxy. Please ensure Tor service is running and proxy is available on port 9050.",
            ).run()
            return
    else:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.settimeout(30)

    # Connection with retry logic
    connected = False
    while True:
        client_socket.connect((host, 9999))
        connected = True
        break

    if not connected:
        return

    client_socket.settimeout(None)
    clear()

    # Handle authentication
    client_socket.sendall(password.encode("utf-8"))
    password_ack = client_socket.recv(1024).decode("utf-8")

    if password_ack.startswith("valid:"):
        _, encryption_key = password_ack.split(":", 1)
        key = bytes.fromhex(encryption_key)
        message_dialog(
            title="Connection Status",
            text="Encryption key received from server.\nAccess Granted.",
        ).run()

        while True:
            nickname = input_dialog(
                title="Nickname", text="Please enter your nickname:"
            ).run()

            if not nickname:
                message_dialog(title="Error", text="Nickname cannot be empty").run()
                client_socket.close()
                return

            client_socket.sendall(nickname.encode("utf-8"))
            response = client_socket.recv(1024)

            if b"nickname_accepted" in response:
                clear()
                break
            elif b"nickname_taken" in response:
                message_dialog(
                    title="Error",
                    text="That nickname is already taken. Please choose another.",
                ).run()
            else:
                message_dialog(
                    title="Error", text=f"Unknown response from server: {response}"
                ).run()

        handle_chat(client_socket, key, nickname)
    else:
        message_dialog(title="Error", text="Invalid password. Connection closed.").run()
        client_socket.close()

    client_socket.close()


if __name__ == "__main__":
    main()
