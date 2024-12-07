# TLS Handshake Formatting Document

## Application Overview
This application provides a TLS handshake which provides a secure connection between a client, a server, and a VPN by verifying each others' identity using certificate from the certificate authority and agreements on keys.

## Format of Unsigned Certificate
$127.0.0.1|65432|(53693, 56533)

## Walkthorough of the steps of a TLS handshake
Before connecting to client through VPN, the server generates a public/private key pair, creates a certificate containing server IP, server port, and public key, and send the formatted certificate to certificate authority for signing.

The certificate authority receives the formatted certificate and signs on the certificate. Then, it sends the signed certificate back to server.

Receiving the signed certificate, the server waits for client's TLS request. Client sends a TLS request to server. Server receives the request and sends the signed certificate to client.

The client receives the signed certificate, verifys the certificate, and extracts server's public key, IP address, and port from the certificate. Then, client double checks whether the server's IP address and port are the correct destination, generates a symmetric key, encrypts the symmetric key using server's public key, and send the encrypted symmetric key to server.

The server receives the encrypted symmetric key and decrypt the key for further use.

The client encrypts the generated symmetric key before sending it to the server. If it doesn't, the VPN will be able to read the symmetric key in transit and use it to decrypt further secure communications between the client and server encrypted and HMAC'd with that key.



## Two ways in which our simulation fails to achieve real security
1. Our simulation skips the process of verifying server's identity with the certificate authority. It makes our simulation vulnerable to imperson attack, which means attackers can pretend they are the correct server and alter the communication between the desired server and client.
2. The encryption and decryption algorithms are relative simple because they preserves the keys as what they are. Therefore, attackers can easily decrypt the messages and ontain the private keys.

## Example Output
**Note: The example output and the command-line traces below are generated based on echo client and server, which means the client input should be the same as the server output.**
**Client Input:** Hello, World
**Server Output** Hello, World

## Command-line Traces
#### certificate_authority.py
Certificate Authority started using public key '(22952, 56533)' and private key '33581'
Certificate authority starting - listening for connections at IP 127.0.0.1 and port 55553
Connected established with ('127.0.0.1', 54202)
Received client message: 'b'$127.0.0.1|65432|(53693, 56533)'' [31 bytes]
Signing '127.0.0.1|65432|(53693, 56533)' and returning it to the client.
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 54202) has closed the remote connection - listening 
Connected established with ('127.0.0.1', 54214)
Received client message: 'b'key'' [3 bytes]
Sending the certificate authority's public key (22952, 56533) to the client
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 54214) has closed the remote connection - listening 

#### secure_server.py
Generated public key '(53693, 56533)' and private key '2840'
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Prepared the formatted unsigned certificate '127.0.0.1|65432|(53693, 56533)'
Connection established, sending certificate '127.0.0.1|65432|(53693, 56533)' to the certificate authority to be signed
Received signed certificate 'D_(33581, 56533)[127.0.0.1|65432|(53693, 56533)]' from the certificate authority
server starting - listening for connections at IP 127.0.0.1 and port 65432
Connected established with ('127.0.0.1', 54216)
---Receiving message from Client
---Checking for TLS Request
---Request Recevied
---Sending Signed Certificate D_(33581, 56533)[127.0.0.1|65432|(53693, 56533)] to Client
---Signed Certificate D_(33581, 56533)[127.0.0.1|65432|(53693, 56533)] Sent
---Waiting for Encrypted Symmetric Key from Client
---Encrypted Symmetric Key b'E_(53693, 56533)[5047]' Received
TLS handshake complete: established symmetric key '5047', acknowledging to client
Received client message: 'b'HMAC_30276[symmetric_5047[Hello, world]]'' [40 bytes]
Decoded message 'Hello, world' from client
Responding 'Hello, world' to the client
Sending encoded response 'HMAC_30276[symmetric_5047[Hello, world]]' back to the client
server is done!

#### VPN.py
VPN starting - listening for connections at IP 127.0.0.1 and port 55554
Connected established with ('127.0.0.1', 54215)
Received client message: 'b'127.0.0.1~IP~65432~port~TLS Request'' [35 bytes]
connecting to server at IP 127.0.0.1 and port 65432
server connection established, sending message 'TLS Request'
message sent to server, waiting for reply
Received server response: 'b'D_(33581, 56533)[127.0.0.1|65432|(53693, 56533)]'' [48 bytes], forwarding to client
Received client message: 'b'E_(53693, 56533)[5047]'' [22 bytes], forwarding to server
Received server response: 'b"symmetric_5047[Symmetric key '5047' received]"' [45 bytes], forwarding to client
Received client message: 'b'HMAC_30276[symmetric_5047[Hello, world]]'' [40 bytes], forwarding to server
Received server response: 'b'HMAC_30276[symmetric_5047[Hello, world]]'' [40 bytes], forwarding to client
VPN is done!

#### secure_client.py
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (22952, 56533) from the certificate authority for verifying certificates
Client starting - connecting to VPN at IP 127.0.0.1 and port 55554
---Sending TLS Request
---Success
---Waiting for Server Response
---Signed Certificate b'D_(33581, 56533)[127.0.0.1|65432|(53693, 56533)]' Received
---Verifying Certificate b'D_(33581, 56533)[127.0.0.1|65432|(53693, 56533)]'
---Verification Succeeded
---Extracting server's public key, IP address, and port
---Extraction Succeeded
---Public Key: (53693, 56533) | Server IP: 127.0.0.1 | Server Port:65432
---Verifying Server IP, Server Port
---Accurate Server IP: 127.0.0.1 Port:65432
---The Client IS Communicating with the port and IP specified in the certificate
---Generate a symmetric key
---Symmetric Key: 5047
---Encrypting the Symmetric Key 5047 using Server's Public Key (53693, 56533)
---Symmetric Key Encrypted: E_(53693, 56533)[5047]
---Sending Encrypted Symmetric Key E_(53693, 56533)[5047] to server
---Success
TLS handshake complete: sent symmetric key '5047', waiting for acknowledgement
Received acknowledgement 'Symmetric key '5047' received', preparing to send message
Sending message 'HMAC_30276[symmetric_5047[Hello, world]]' to the server
Message sent, waiting for reply
Received raw response: 'b'HMAC_30276[symmetric_5047[Hello, world]]'' [40 bytes]
Decoded message 'Hello, world' from server
client is done!

## Acknowledgements