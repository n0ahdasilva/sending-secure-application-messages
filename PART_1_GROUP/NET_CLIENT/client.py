import rsa
import socket
import sys


def generate_key_pair():
    # Generate assymetric RSA key pairs of 2048-bit length.
    CLIENT_PUB_KEY, CLIENT_PRV_KEY = rsa.newkeys(2048)

    # Save the public key and private key to .pem file types.
    with open("../client_public.pem", "wb") as f:
        f.write(CLIENT_PUB_KEY.save_pkcs1("PEM"))

    with open("client_private.pem", "wb") as f:
        f.write(CLIENT_PRV_KEY.save_pkcs1("PEM"))

    # Erase keys from variables.
    CLIENT_PUB_KEY = None
    CLIENT_PRV_KEY = None

    # Exit the program to not run socket.
    sys.exit()


def send_msg(socket, msg):
    # NOTE: MESSAGE INTEGRITY & SENDER AUTHENTICATION    
    # Fetch the client's private key.
    with open("client_private.pem", "rb") as f:
        CLIENT_PRV_KEY = rsa.PrivateKey.load_pkcs1(f.read())
    # Hash the message using the SHA256 algorithm and sign the hash digest using the client's private key.
    hash_digest_signature = rsa.sign(msg.encode("utf-8"), CLIENT_PRV_KEY, "SHA-256")

    # NOTE: MESSAGE CONFIDENTIALITY
    # Fetch the server's public key.
    with open("../server_public.pem", "rb") as f:
        SERVER_PUB_KEY = rsa.PublicKey.load_pkcs1(f.read())
    # Encrypt the message using the server's public key.
    encr_msg = rsa.encrypt(msg.encode("utf-8"), SERVER_PUB_KEY)
    
    # Finally, send the encrypted message to the server, along with its signed hash digest.
    socket.send(hash_digest_signature)
    socket.send(encr_msg)

    # Proof message can't be intercepted.
    print("\nIntercepting the message while in transit would look like this:")
    print(encr_msg)

    print("\nIntercepting the digital signature while in transit would look like this:")
    print(hash_digest_signature)


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
    print(s.recv(1024).decode("utf-8"))

    # Checking the command line for arguments.
    if len(sys.argv) > 1:
        # If the first arg (the command) is requesting to send a message to the server...
        if sys.argv[1] == "send_msg":
            # Run the respective function with the message to send.
            send_msg(socket=s, msg=sys.argv[2])
        # If the first arg (the command) is invalid, let the client know.
        else:
            print("Invalid command")


# Run the code
if __name__ == "__main__":
    main()