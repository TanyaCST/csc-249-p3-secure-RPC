# TLS Handshake Formatting Document

## Application Overview



## Sample Output
#### certificate_authority.py
Certificate Authority started using public key '(26722, 56533)' and private key '29811'
Certificate authority starting - listening for connections at IP 127.0.0.1 and port 55553
Connected established with ('127.0.0.1', 53787)
Received client message: 'b'$127.0.0.1|65432|(47583, 56533)'' [31 bytes]
Signing '127.0.0.1|65432|(47583, 56533)' and returning it to the client.
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 53787) has closed the remote connection - listening 
Connected established with ('127.0.0.1', 53791)
Received client message: 'b'key'' [3 bytes]
Sending the certificate authority's public key (26722, 56533) to the client
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 53791) has closed the remote connection - listening

#### secure_server.py
Generated public key '(47583, 56533)' and private key '8950'
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Prepared the formatted unsigned certificate '127.0.0.1|65432|(47583, 56533)'
Connection established, sending certificate '127.0.0.1|65432|(47583, 56533)' to the certificate authority to be signed
Received signed certificate 'D_(29811, 56533)[127.0.0.1|65432|(47583, 56533)]' from the certificate authority
server starting - listening for connections at IP 127.0.0.1 and port 65432
Connected established with ('127.0.0.1', 53793)
---Receiving message from Client
---Checking for TLS Request
---Request Recevied
---Sending Signed Certificate D_(29811, 56533)[127.0.0.1|65432|(47583, 56533)] to Client
---Signed Certificate D_(29811, 56533)[127.0.0.1|65432|(47583, 56533)] Sent
---Waiting for Encrypted Symmetric Key from Client
---Encrypted Symmetric Key b'E_(47583, 56533)[62217]' Received
TLS handshake complete: established symmetric key 'b'E_(47583, 56533)[62217]'', acknowledging to client
Traceback (most recent call last):
  File "/Users/tanyachen/Documents/csc249/csc-249-p3-secure-RPC/cryptgraphy_simulator.py", line 24, in _to_int
    return int(x)
ValueError: invalid literal for int() with base 10: 'E_(47583, 56533)[62217]'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/Users/tanyachen/Documents/csc249/csc-249-p3-secure-RPC/secure_server.py", line 106, in <module>
    conn.sendall(bytes(cryptgraphy_simulator.symmetric_encrypt(symmetric_key, f"Symmetric key '{symmetric_key}' received"), 'utf-8'))
  File "/Users/tanyachen/Documents/csc249/csc-249-p3-secure-RPC/cryptgraphy_simulator.py", line 85, in symmetric_encrypt
    key = _to_int(key); message = _to_str(message)
  File "/Users/tanyachen/Documents/csc249/csc-249-p3-secure-RPC/cryptgraphy_simulator.py", line 26, in _to_int
    raise AssertionError(f"'{x}' (of type '{type(x)}') cannot be converted to an int")
AssertionError: 'E_(47583, 56533)[62217]' (of type '<class 'str'>') cannot be converted to an int
tanyachen@TnyMacBook-Pro csc-249-p3-secure-RPC % 

#### VPN.py
VPN starting - listening for connections at IP 127.0.0.1 and port 55554
Connected established with ('127.0.0.1', 53792)
Received client message: 'b'127.0.0.1~IP~65432~port~TLS Request'' [35 bytes]
connecting to server at IP 127.0.0.1 and port 65432
server connection established, sending message 'TLS Request'
message sent to server, waiting for reply
Received server response: 'b'D_(29811, 56533)[127.0.0.1|65432|(47583, 56533)]'' [48 bytes], forwarding to client
Received client message: 'b'E_(47583, 56533)[62217]'' [23 bytes], forwarding to server
VPN is done!

#### secure_client.py
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (26722, 56533) from the certificate authority for verifying certificates
Client starting - connecting to VPN at IP 127.0.0.1 and port 55554
---Sending TLS Request
---Success
---Waiting for Server Response
---Signed Certificate b'D_(29811, 56533)[127.0.0.1|65432|(47583, 56533)]' Received
---Verifying Certificate b'D_(29811, 56533)[127.0.0.1|65432|(47583, 56533)]'
---Verification Succeeded
---Extracting server's public key, IP address, and port
---Extraction Succeeded
---Public Key: (47583, 56533) | Server IP: 127.0.0.1 | Server Port:65432
---Verifying Server IP, Server Port
---The Client **IS NOT** Communicating with the port and IP specified in the certificate
---Generate a symmetric key
---Symmetric Key: 62217
---Encrypting the Symmetric Key 62217 using Server's Public Key (47583, 56533)
---Symmetric Key Encrypted: E_(47583, 56533)[62217]
---Sending Encrypted Symmetric Key E_(47583, 56533)[62217] to server
---Success
TLS handshake complete: sent symmetric key 'E_(47583, 56533)[62217]', waiting for acknowledgement
Traceback (most recent call last):
  File "/Users/tanyachen/Documents/csc249/csc-249-p3-secure-RPC/cryptgraphy_simulator.py", line 24, in _to_int
    return int(x)
ValueError: invalid literal for int() with base 10: 'E_(47583, 56533)[62217]'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/Users/tanyachen/Documents/csc249/csc-249-p3-secure-RPC/secure_client.py", line 111, in <module>
    print(f"Received acknowledgement '{cryptgraphy_simulator.symmetric_decrypt(symmetric_key, data)}', preparing to send message")
  File "/Users/tanyachen/Documents/csc249/csc-249-p3-secure-RPC/cryptgraphy_simulator.py", line 90, in symmetric_decrypt
    key = _to_int(key); cyphertext = _to_str(cyphertext)
  File "/Users/tanyachen/Documents/csc249/csc-249-p3-secure-RPC/cryptgraphy_simulator.py", line 26, in _to_int
    raise AssertionError(f"'{x}' (of type '{type(x)}') cannot be converted to an int")
AssertionError: 'E_(47583, 56533)[62217]' (of type '<class 'str'>') cannot be converted to an int
tanyachen@TnyMacBook-Pro csc-249-p3-secure-RPC % 

## Reference