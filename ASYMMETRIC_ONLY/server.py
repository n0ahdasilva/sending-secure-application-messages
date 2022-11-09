#
#   PROJECT : Sending Secure Application Messages
# 
#   FILENAME : ASYMMETRIC_ONLY/server.py
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


def recv_msg(c_socket):
    # Request the encrypted digital signature and message, while sending receipt confirmations.
    signature = c_socket.recv(10240)
    c_socket.send(bytes(f"Received digital signature", "utf-8"))
    msg = c_socket.recv(10240)
    c_socket.send(bytes(f"Received message", "utf-8"))

    try:
        # NOTE: MESSAGE CONFIDENTIALITY
        # Fetch the server's private key.
        with open("server_private.pem", "rb") as f:
            SERVER_PRV_KEY = rsa.PrivateKey.load_pkcs1(f.read())
        # Decrypt the message using the server's private key.
        decr_msg = rsa.decrypt(msg, SERVER_PRV_KEY).decode("utf-8")
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
        rsa.verify(decr_msg.encode("utf-8"), signature, CLIENT_PUB_KEY)
    except:
        print("Message integrity & sender authentication failed.")
    else:
        print("Message integrity & sender authentication passed.")
    
    # Finally, send the encrypted message to the server, along with its signed hash digest.
    try:
        print(decr_msg)
    except:
        print("Unable to print out message.")

def main():
    # Max size of messages (1,000,000,000)
    HEADERSIZE = 10

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
        client_socket.send(bytes(f"Connected to server {socket.gethostname()}:8000.", "utf-8"))

        # Receive and process message from client.
        recv_msg(c_socket=client_socket)

        # Close the socket after last request between client and server.
        client_socket.close()


if __name__ == "__main__":
    main()