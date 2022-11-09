# sending-secure-application-messages
Establish a connection that sends secure application messages from a client to a server using the Python programming language. This process is similar to components that exist in many applications (e.g. secure email, SSH, ..). The secure connection should provide:

• Message confidentiality,

• Sender authentication,

• Message integrity,

• and symmetric key distribution


## Part 1

• All messages from client to the server are confidential. It is assumed both ends trust the public keys.

• Employ the diagram to allow the server to verify it is receiving the message from the client and not anyone else.

• Server should verify the received message has remained intact all the way it traveled from the Client.

• Demonstrate no one can read the message even if they could intercept the message in the transit.


## Part 2

In part 1 of the assignment, the message was encrypted by asymmetric key, using the server’s public key. This is not an efficient approach for large messages. For part 2 of the assignment, you need to modify the program to fulfill the following features:

• The client generates a secret key and uses a symmetric algorithm to encrypt the message and signature

• The client uses the server’s public key to encrypt the secret key.

• It sends the output of last 2 steps, step 1 and 2, to the server.


## How it works