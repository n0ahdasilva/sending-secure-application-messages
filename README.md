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


## Running the code

To run the specific version of the encrypted messaging, you'll need to run the files from their respective sub-directories.

i.e.: `./ASYMMETRIC_ONLY` or `./ASYMMETRIC_SYMMETRIC`

First, start the server: `python -u server.py`

To receive a message from the server, the command is as follows:

`python -u client.py recv_msg`

To send a message to the server, the command is as follows:

`python -u client.py send_msg "message_to_send"`

You are also able to generate new RSA key pair on either the client or server by issuing the `generate_key_pair` command.

`python -u client.py generate_key_pair`

`python -u server.py generate_key_pair`


## How it works

For this explaination, ALICE and BOB will be used to describe either side of the connection.

### Asymmetric ONLY

When Alice wants to send a secret message to Bob, she will need to encrypt it to prevent anyone from reading it. To ensure only Bob can access the message, Alice uses asymmetric keys usually RSA key pairs, which requires one key to encrypt the message and another different key to decrypt the message.

In this case, since Alic only wants Bob to have access to the message, she will use Bob public key to encrypt the data. While anyone has access to Bob's public key, it cannot be used to decrypt the data. Only Bob will be able to do so, using his private key.

Though this solution is enough to provide confidentiality, there is still the issue of the integrity and authentication of the sent message.

To address this, Alice will also have to hash the message using an algorithm of choice, SHA256 is used in this example. Hashing provides a digest, which is cannot be reverted to its original form and is unique. If two different pieces of data share the same hash digest, this algorithm would be considered broken. The hash digest can be compared the receive message's hash in the same algorithm, to confirm it stay intact and was not tampered.

Using the digest from the hashed message, Alice can then sign that piece of data using her own private key, to prove that the message in fact came from her, since Bob can use Alice's public key to validate the signature.

In the end, Bob is able to verify the signature and decrypt the message, ensuring he received it from Alice, without anyone intercepting it.


### Asymmetric & Symmetric

The process using both pairs of RSA keys and a secret symmetric key is fairly similar to the latter example.

The process of generating the digital signature is identical.

In this case, we modify how the message is encrypted.

Instead of using Bob's public key to encrypt the message, Alice packages the signature and message into a data block, then encrypts the whole block using a symmetric key generated on-demand.

Bob needs to get access to the symmetric key in order to decrypt the data. To do this, Alice encrypts the symmetric key using Bob's public key, in order to guarantee that Bob is the only other person with access to the symmetric key.

Finally, Alice sends the encrypted data block and the encrypted symmetric key over to Bob for him to decypher and receive.