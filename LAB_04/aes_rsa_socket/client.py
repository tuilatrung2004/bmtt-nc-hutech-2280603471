from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import hashlib

# Initialize client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client_socket.connect(('localhost', 12345))
    print("Connected to server.")

    # Generate RSA key pair for the client
    client_key = RSA.generate(2048)
    print("Client RSA key pair generated.")

    # Receive server's public key
    # Using a larger buffer for key reception as RSA keys are relatively large
    server_public_key = RSA.import_key(client_socket.recv(2048))
    print("Received server's public key.")

    # Send client's public key to the server
    client_socket.send(client_key.publickey().export_key(format='PEM'))
    print("Sent client's public key to server.")

    # Receive encrypted AES key from the server
    encrypted_aes_key = client_socket.recv(2048)
    print("Received encrypted AES key from server.")

    # Decrypt the AES key using client's private RSA key
    cipher_rsa = PKCS1_OAEP.new(client_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print("Decrypted AES key successfully.")

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

    # Function to receive messages from server in a separate thread
    def receive_messages():
        while True:
            try:
                # Receive encrypted message from the server
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message: # If no data is received, server disconnected
                    print("Server disconnected.")
                    break
                
                # Decrypt the received message
                decrypted_message = decrypt_message(aes_key, encrypted_message)
                print("Received:", decrypted_message)
            except Exception as e:
                print(f"Error receiving message: {e}")
                break # Exit loop on error (e.g., connection reset)

    # Start the receiving thread to listen for incoming messages from the server
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.daemon = True # Allow main program to exit even if this thread is running
    receive_thread.start()

    # Main loop for sending messages from the client
    while True:
        message = input("Enter message ('exit' to quit): ")
        
        # Encrypt the message before sending
        encrypted_message = encrypt_message(aes_key, message)
        
        # Send the encrypted message to the server
        client_socket.send(encrypted_message)

        # If the user types "exit", break the loop to close the client connection
        if message.lower() == "exit":
            print("Exiting chat.")
            break

except ConnectionRefusedError:
    print("Connection refused. Make sure the server is running and accessible at localhost:12345.")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    # Ensure the client socket is closed when the program exits or an error occurs
    client_socket.close()
    print("Client socket closed.")