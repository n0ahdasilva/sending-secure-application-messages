#
#   PROJECT : Sending Secure Application Messages
# 
#   FILENAME : ASYMMETRIC_SYMETRIC/client.py
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
    CLIENT_PUB_KEY, CLIENT_PRV_KEY = rsa.newkeys(2048)

    # Save the public key and private key to .pem file types.
    with open("client_public.pem", "wb") as f:
        f.write(CLIENT_PUB_KEY.save_pkcs1("PEM"))

    with open("client_private.pem", "wb") as f:
        f.write(CLIENT_PRV_KEY.save_pkcs1("PEM"))

    # Erase keys from variables.
    CLIENT_PUB_KEY = None
    CLIENT_PRV_KEY = None

    # Exit the program to not run socket.
    sys.exit()


def send_msg(socket, msg):
    # Generate a random symmetric key.
    symmetric_key = Fernet.generate_key()

    # NOTE: MESSAGE INTEGRITY & SENDER AUTHENTICATION    
    # Fetch the client's private key.
    with open("client_private.pem", "rb") as f:
        CLIENT_PRV_KEY = rsa.PrivateKey.load_pkcs1(f.read())
    # Hash the message using the SHA256 algorithm and sign the hash digest using the client's private key.
    hash_digest_signature = rsa.sign(msg.encode("utf-8"), CLIENT_PRV_KEY, "SHA-256")
    # NOTE: MESSAGE CONFIDENTIALITY
    # Fetch the server's public key.
    with open("server_public.pem", "rb") as f:
        SERVER_PUB_KEY = rsa.PublicKey.load_pkcs1(f.read())
    # Create data block containing the signature and message.
    data_block = [list(hash_digest_signature), msg]
    
    # Encrypt the data block using the symmetric key.
    encr_data_block = Fernet(symmetric_key).encrypt(bytes(str(data_block).encode("utf-8")))
    # Encrypt the symmetric key using the server's public key.
    encr_symmetric_key = rsa.encrypt(symmetric_key, SERVER_PUB_KEY)

    # Finally, send the encrypted message to the server, along with its signed hash digest.
    socket.send(encr_symmetric_key)
    socket.recv(1024)   # Get receipt confirmation
    socket.send(encr_data_block)
    socket.recv(1024)   # Get receipt confirmation

    # Proof message can't be intercepted.
    print("\nIntercepting the data block while in transit would look like this:")
    print(encr_data_block)
    print("\nIntercepting the symmetric key while in transit would look like this:")
    print(hash_digest_signature)


def recv_msg(socket):
    # Request the encrypted symmetric key and data block, while sending receipt confirmations.
    encr_symmetric_key = socket.recv(10240)
    socket.send(bytes(f"Received symmetric key", "utf-8"))
    encr_data_block = socket.recv(10240)
    socket.send(bytes(f"Received data block", "utf-8"))

    try:
        # NOTE: MESSAGE CONFIDENTIALITY
        # Fetch the client's private key.
        with open("client_private.pem", "rb") as f:
            CLIENT_PRV_KEY = rsa.PrivateKey.load_pkcs1(f.read())
        # Decrypt the symmetric using the server's private key.
        decr_symmetric_key = rsa.decrypt(encr_symmetric_key, CLIENT_PRV_KEY)

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
        # Fetch the server's public key.
        with open("server_public.pem", "rb") as f:
            SERVER_PUB_KEY = rsa.PublicKey.load_pkcs1(f.read())
        # Verify the hash digest signature using the client's public key.
        rsa.verify(msg.encode("utf-8"), hash_digest_signature, SERVER_PUB_KEY)
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
    # If client wants to generate keys, do not run socket code.
    if len(sys.argv) > 1:
        # If the first arg (the command) is requesting to generate keys...
        if sys.argv[1] == "generate_key_pair":
            # Run the respective function.
            generate_key_pair()
    
    # Define socket object with AF_INET (IPv4) family type and SOCK_STREAM (TCP) socket type.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the server (this computer), on port 8000.
    s.connect((socket.gethostname(), 8000))

    # Tell the client they are connected.
    print(s.recv(2048).decode("utf-8"))

    # Checking the command line for arguments.
    if len(sys.argv) > 1:
        # If the first arg (the command) is requesting to send a message to the server...
        if sys.argv[1] == "send_msg":
            # Run the respective function with the message to send.
            s.send(sys.argv[1].encode("utf-8"))
            send_msg(socket=s, msg=sys.argv[2])
        elif sys.argv[1] == "recv_msg":
            # Run the respective function.
            s.send(sys.argv[1].encode("utf-8"))
            recv_msg(socket=s)
        # If the first arg (the command) is invalid, let the client know.
        else:
            s.send(sys.argv[1].encode("utf-8"))
            print("Invalid command")


# Run the code
if __name__ == "__main__":
    main()