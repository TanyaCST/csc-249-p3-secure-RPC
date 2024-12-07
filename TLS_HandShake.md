# TLS Handshake Formatting Document

## Application Overview



## Sample Output
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

## Reference