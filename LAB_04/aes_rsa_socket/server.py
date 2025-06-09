from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import hashlib

# Initialize server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

# Generate RSA key pair
server_key = RSA.generate(2048)

# List of connected clients (stores (socket, AES key) tuples)
clients = []

# Function to encrypt message using AES
def encrypt_message(key, message):
    # Create a new AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the message to be a multiple of AES block size, then encode and encrypt it
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    # Return the initialization vector (IV) prepended to the ciphertext
    return cipher.iv + ciphertext

# Function to decrypt message using AES
def decrypt_message(key, encrypted_message):
    # Extract the initialization vector (IV) from the beginning of the encrypted message
    iv = encrypted_message[:AES.block_size]
    # Extract the actual ciphertext
    ciphertext = encrypted_message[AES.block_size:]
    # Create a new AES cipher in CBC mode with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the ciphertext and unpad it
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    # Decode the decrypted message from bytes to a string
    return decrypted_message.decode()

# Function to handle individual client connections
def handle_client(client_socket, client_address):
    print(f"Connected with {client_address}")

    try:
        # Send server's public key to client
        client_socket.send(server_key.publickey().export_key(format='PEM'))

        # Receive client's public key
        # Using a larger buffer for key reception as RSA keys are relatively large
        client_received_key = RSA.import_key(client_socket.recv(2048))

        # Generate a symmetric AES key (16 bytes for AES-128) for message encryption
        aes_key = get_random_bytes(16)

        # Encrypt the generated AES key using the client's public RSA key
        # PKCS1_OAEP is used for secure RSA encryption
        cipher_rsa = PKCS1_OAEP.new(client_received_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Send the encrypted AES key to the client
        client_socket.send(encrypted_aes_key)

        # Add the client's socket and their unique AES key to the list of active clients
        clients.append((client_socket, aes_key))
        print(f"AES key established with {client_address}")

        # Loop indefinitely to receive messages from this client
        while True:
            # Receive encrypted message from the client
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message: # If no data is received, connection might be closed
                print(f"Client {client_address} disconnected unexpectedly.")
                break

            # Decrypt the received message
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print(f"Received from {client_address}: {decrypted_message}")

            # If the client sends "exit", break the loop to close the connection
            if decrypted_message.lower() == "exit":
                print(f"Client {client_address} requested to exit.")
                break

            # Send the received message to all other connected clients (broadcast)
            # Iterate through a copy of the clients list to avoid issues if clients disconnect during iteration
            for client, key in list(clients):
                if client != client_socket: # Don't send the message back to the sender
                    try:
                        encrypted = encrypt_message(key, decrypted_message)
                        client.send(encrypted)
                    except Exception as e:
                        print(f"Error sending to client {client.getpeername()}: {e}")
                        # Optionally remove problematic client here if send fails consistently
                        # clients.remove((client, key))

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        # This block ensures cleanup happens whether there's an error or normal exit
        if (client_socket, aes_key) in clients:
            clients.remove((client_socket, aes_key))
            print(f"Removed {client_address} from active clients list.")
        client_socket.close()
        print(f"Connection with {client_address} closed.")

# Main loop to accept new client connections
print("Server is listening for incoming connections...")
while True:
    try:
        # Accept a new client connection
        client_socket, client_address = server_socket.accept()
        # Create a new thread to handle this client concurrently
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()
    except Exception as e:
        print(f"Error accepting new connection: {e}")
        break # Exit server loop if an error occurs here (e.g., server socket closed)