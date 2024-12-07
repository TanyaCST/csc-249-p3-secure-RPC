# TLS Handshake Formatting Document

## Application Overview



## Sample Output
### The 
#### certificate_authority.py
Certificate Authority started using public key '(19156, 56533)' and private key '37377'
Certificate authority starting - listening for connections at IP 127.0.0.1 and port 55553
Connected established with ('127.0.0.1', 52725)
Received client message: 'b'$127.0.0.1|65432|(55425, 56533)'' [31 bytes]
Signing '127.0.0.1|65432|(55425, 56533)' and returning it to the client.
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 52725) has closed the remote connection - listening 
Connected established with ('127.0.0.1', 52728)
Received client message: 'b'key'' [3 bytes]
Sending the certificate authority's public key (19156, 56533) to the client
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 52728) has closed the remote connection - listening 

#### secure_server.py

#### VPN.py

#### secure_client.py