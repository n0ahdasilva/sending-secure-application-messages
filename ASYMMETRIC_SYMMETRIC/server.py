#
#   PROJECT : Sending Secure Application Messages
# 
#   FILENAME : ASYMMETRIC_SYMETRIC/server.py
# 
#   DESCRIPTION :
#       Establish a connection that sends secure application messages from a client
#       to a server using the Python programming language. This process is similar 
#       to components that exist in many applications (e.g. secure email, SSH, ..).
# 
#   FUNCTIONS :
#       generate_key_pairs()
#       send_msg()
#       recv_msg()
#       main()
# 
#   NOTES :
#      - ...
# 
#   AUTHOR(S) : Noah Arcand Da Silva    START DATE : 2022.11.08 (YYYY.MM.DD)
#
#   CHANGES :
#       - Random errors occured when sending twice in a row with sockets. To
#       mitigate this issue, each consecutive send needed to be followed with
#       a receive from the other side.
# 
#   VERSION     DATE        WHO             DETAILS
#   0.0.1a      2022.11.08  Noah            Creation of project.
#   0.0.1b      2022.11.08  Noah            Functional version of asymmetric encryption.
#   0.0.1c      2022.11.09  Noah            Bi-directional flow for asymmetric and symmetric encryption.
#


import cryptography
from cryptography.fernet import Fernet
import rsa
import socket
import sys


def generate_key_pair():
    # Generate asymmetric RSA key pairs of 2048-bit length.
    SERVER_PUB_KEY, SERVER_PRV_KEY = rsa.newkeys(2048)
    
    # Save the public key and private key to .pem file types.
    with open("server_public.pem", "wb") as f:
        f.write(SERVER_PUB_KEY.save_pkcs1("PEM"))

    with open("server_private.pem", "wb") as f:
        f.write(SERVER_PRV_KEY.save_pkcs1("PEM"))

    # Erase keys from variables.
    SERVER_PUB_KEY = None
    SERVER_PRV_KEY = None

    # Exit the program to not run socket.
    sys.exit()


def send_msg(c_socket, msg):
    # Generate a random symmetric key.
    symmetric_key = Fernet.generate_key()

    # NOTE: MESSAGE INTEGRITY & SENDER AUTHENTICATION    
    # Fetch the server's private key.
    with open("server_private.pem", "rb") as f:
        SERVER_PRV_KEY = rsa.PrivateKey.load_pkcs1(f.read())
    # Hash the message using the SHA256 algorithm and sign the hash digest using the client's private key.
    hash_digest_signature = rsa.sign(msg.encode("utf-8"), SERVER_PRV_KEY, "SHA-256")
    # NOTE: MESSAGE CONFIDENTIALITY
    # Fetch the server's public key.
    with open("client_public.pem", "rb") as f:
        CLIENT_PUB_KEY = rsa.PublicKey.load_pkcs1(f.read())
    # Create data block containing the signature and message.
    data_block = [list(hash_digest_signature), msg]
    
    # Encrypt the data block using the symmetric key.
    encr_data_block = Fernet(symmetric_key).encrypt(bytes(str(data_block).encode("utf-8")))
    # Encrypt the symmetric key using the server's public key.
    encr_symmetric_key = rsa.encrypt(symmetric_key, CLIENT_PUB_KEY)

    # Finally, send the encrypted message to the server, along with its signed hash digest.
    c_socket.send(encr_symmetric_key)
    c_socket.recv(1024)   # Get receipt confirmation
    c_socket.send(encr_data_block)
    c_socket.recv(1024)   # Get receipt confirmation

    # Proof message can't be intercepted.
    print("\nIntercepting the data block while in transit would look like this:")
    print(encr_data_block)
    print("\nIntercepting the symmetric key while in transit would look like this:")
    print(hash_digest_signature)


def recv_msg(c_socket):
    # Request the encrypted symmetric key and data block, while sending receipt confirmations.
    encr_symmetric_key = c_socket.recv(10240)
    c_socket.send(bytes(f"Received symmetric key", "utf-8"))
    encr_data_block = c_socket.recv(10240)
    c_socket.send(bytes(f"Received data block", "utf-8"))

    try:
        # NOTE: MESSAGE CONFIDENTIALITY
        # Fetch the server's private key.
        with open("server_private.pem", "rb") as f:
            SERVER_PRV_KEY = rsa.PrivateKey.load_pkcs1(f.read())
        # Decrypt the symmetric using the server's private key.
        decr_symmetric_key = rsa.decrypt(encr_symmetric_key, SERVER_PRV_KEY)

        # With the symmetric key, decrypt the data block.
        decr_data_block = Fernet(decr_symmetric_key).decrypt(encr_data_block).decode("utf-8")
        # Seperate the data block's variables.
        hash_digest_signature = bytes([int(i) for i in decr_data_block[2:decr_data_block.find("], '")].split(", ")])
        msg = decr_data_block[decr_data_block.find("], '") + 4:-2]
    except:
        print("Message confidentiality failed.")
    else:
        print("Message confidentiality passed.")
    
    try:
        # NOTE: MESSAGE INTEGRITY & SENDER AUTHENTICATION    
        # Fetch the client's public key.
        with open("client_public.pem", "rb") as f:
            CLIENT_PUB_KEY = rsa.PublicKey.load_pkcs1(f.read())
        # Verify the hash digest signature using the client's public key.
        rsa.verify(msg.encode("utf-8"), hash_digest_signature, CLIENT_PUB_KEY)
    except:
        print("Message integrity & sender authentication failed.")
    else:
        print("Message integrity & sender authentication passed.")
    
    # Finally, print the encrypted message.
    try:
        print(msg)
    except:
        print("Unable to print out message.")

def main():
    # Checking the command line for arguments.
    if len(sys.argv) > 1:
        # If the first arg (the command) is requesting to generate keys...
        if sys.argv[1] == "generate_key_pair":
            # Run the respective function.
            generate_key_pair()
    
    # Define socket object with AF_INET (IPv4) family type and SOCK_STREAM (TCP) socket type.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the hostname of this computer, on port 8000.
    s.bind((socket.gethostname(), 8000))
    # Add a queue of 1. For demonstration, we will only be using 1 client at a time.
    s.listen(1)

    # Checking the command line for arguments.
    if len(sys.argv) > 1:
        print("Invalid command")

    while True:
        # Accept client socket connections, store client socket object and its source address.
        client_socket, client_address = s.accept()
        
        print(f"Connection from {client_address} has been established.")
        # Tell the client they are connected to the server
        client_socket.send(bytes(f"Connected to server {socket.gethostname()}:{s.getsockname()[1]}.", "utf-8"))

        client_request = client_socket.recv(1024).decode("utf-8")
        if client_request == 'send_msg':              # Receive and process message from client.
            recv_msg(
                c_socket = client_socket
            )
        elif client_request == 'recv_msg':
            send_msg(
                c_socket = client_socket,
                msg="This is a message from the server!"
            )
        else:
            print(f"Client typed in an invalid command: {client_request}")

        # Close the socket after last request between client and server.
        client_socket.close()


if __name__ == "__main__":
    main()