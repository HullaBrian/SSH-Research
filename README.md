# SSH-Research
A collection of all the research I have done into the SSH protcol and the steps taken by it to establish secure connections.

The purpose of this repository is lay out the SSH protocol in a neat, easy to read manner.
If you're anything like me, then you'll have a hard time understanding the RFC's that outline SSH.

All official sources of information regarding the SSH protocol can be found through this website
https://rfcs.io/ssh

## Disclaimers
- For the purposes of this document, the initial TCP connection will not be covered. Only the extended processes done by the SSH protocol will be examined
- It is possible that there will be errors in this document. Should that happen, please create a pull request in the [github repository](https://github.com/hullabrian/SSH-Research)
- For my own purposes, I may include examples of steps in the SSH connection process in the form of either Python or C code. This code is not guaranteed to work, nor am I liable for any damages done by this code.
	- The code provided attempts to write a pure python implementation of the SSH protocol.

# Overview
The SSH protocol can be broken into several steps and processes:
1. The client sends a request to the server to establish a connection.
2.  The server responds with its public host key, which the client stores in its known_hosts file.
3.  The client generates a random number, called a "challenge," and encrypts it using the server's public key.
4.  The client sends the encrypted challenge to the server.
5.  The server decrypts the challenge using its private key and sends it back to the client, along with a message authentication code (MAC) to ensure the integrity of the message.
6.  The client verifies the MAC and, if it is valid, generates a session key, which it encrypts using the server's public key.
7.  The client sends the encrypted session key to the server.
8.  The server decrypts the session key using its private key and both the client and server can now use the session key to encrypt and decrypt messages transmitted between them.

# Step 1: SSH version exchange
When an SSH client connects to an SSH server, it sends a message called an "SSH protocol identification string" to the server. This message includes the client's SSH version number, as well as some other information about the client's capabilities.

Here is an example of an SSH protocol identification string:

```SSH-2.0-MySSHClient```

In this example, "SSH-2.0" indicates the version of the SSH protocol being used, and "MySSHClient" is the name and version of the client software.

The SSH protocol identification string is sent by the client as the first message in the connection process. The server receives this message and uses it to determine which version of the SSH protocol the client is using and whether it is compatible with the server.

If the server is unable to support the version of the SSH protocol that the client is using, it will terminate the connection. Otherwise, it will continue with the authentication process and establish a secure connection with the client.

## Protocol Mismatch
If the client's SSH version is not compatible with the server, the server will return a message indicating that the connection has been terminated. This message is called an "SSH protocol error message," and it is used to inform the client that the connection could not be established due to a protocol-related issue.

Here is an example of an SSH protocol error message:

`Protocol mismatch.`

This message indicates that the client and server are using different versions of the SSH protocol and are unable to communicate with each other.

In general, the SSH protocol error message will include information about the specific issue that caused the connection to be terminated. This can help the client and server troubleshoot the problem and determine the cause of the compatibility issue.

It is important for the client and server to use compatible versions of the SSH protocol in order to establish a secure connection. If the client's version is not compatible with the server, the connection will not be established and the client will be unable to access the server's resources.

## Python Implementation
```python
import socket

HOST: str = '127.0.0.1'  # Connect to local host
PORT: int = 22  # Standard SSH port

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.connect((HOST, PORT))
	
	s.sendall(b"SSH-2.0-SSH_CLIENT-1.0")  # Send SSH client version to server
	
	server_ssh_version: str = s.recv(32768).decode("utf-8")  # Receive SSH servr version
	if "Protocol mismatch." in server_ssh_version:
		s.close()
		print("Incompatible SSH client!")
		raise(socket.error)

```

# Step 2: Key Exchange
## Deciding what algorithm to use
During the key exchange process, the client and server negotiate which key exchange algorithm to use. This negotiation is done using the Key Exchange Algorithms (KEX) section of the SSH protocol.

The client and server each send a list of supported key exchange algorithms to each other, in order of preference. The first algorithm that both the client and server support is then used for the key exchange. If the client and server do not have any algorithms in common, the connection will fail.

For example, if the client supports the algorithms "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", and "diffie-hellman-group-exchange-sha1", and the server supports the algorithms "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", and "diffie-hellman-group1-sha1", then the key exchange algorithm "diffie-hellman-group14-sha1" would be used, as it is the first algorithm that both the client and server support.

### Packet Format
To properly send the key exchange packet, the following format must be followed:

```
PACKET LENGTH: int
PADDING LENGTH: int
MESSAGE CODE KEX INIT: 20
COOKIE: hex : bytearray.fromhex(secrets.token_hex(16))
KEX ALGORITHMS LENGTH: len(kex_algs_string)
KEX ALGORITHMS STRING: kex_algs_string
SERVER HOST KEY ALGORITHMS LENGTH: len(server_host_key_algs)
SERVER HOST KEY ALGORITHMS STRING: server_host_key_algs
ENCRYPTION ALGORITHMS CLIENT TO SERVER LENGTH: len(encryption_algs)
ENCRYPTION ALGORITHMS CLIENT TO SERVER STRING: encryption_algs
ENCRYPTION ALGORITHMS SERVER TO CLIENT LENGTH: len(encryption_algs)
ENCRYPTION ALGORITHMS SERVER TO CLIENT STRING: encryption_algs
MAC ALGORITHMS CLIENT TO SERVER LENGTH: len(mac_algs)
MAC ALGORITHMS CLIENT TO SERVER STRING: mac_algs
MAC ALGORITHMS SERVER TO CLIENT LENGTH: len(mac_algs)
MAC ALGORITHMS SERVER TO CLIENT STRING: mac_algs
COMPRESSION ALGORITHMS CLIENT TO SERVER LENGTH: len(compression_algs)
COMPRESSION ALGORITHMS CLIENT TO SERVER STRING: compression_algs
COMPRESSION ALGORITHMS SERVER TO CLIENT LENGTH: len(compression_algs)
COMPRESSION ALGORITHMS SERVER TO CLIENT STRING: compression_algs
LANGUAGES CLIENT TO SERVER LENGTH: len(languages)
LANGUAGES CLIENT TO SERVER STRING: languages
LANGUAGES SERVER TO CLIENT LENGTH: len(languages)
LANGUAGES SERVER TO CLIENT STRING: languages
FIRST KEX PACKET FOLLOWS: 0
RESERVED: 0
PADDING STRING: 0
```

When this packet is sent to the server from the client, the server should respond to the client with a packet with the same format.

### Algorithms
The following algorithms are listed under [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253)
All algorithms mentioned **must** be sent to the server in a comma seperated list. The following code is a python implementation to convert a list of strings into the bytes of a string containing the comma seperated list.

```python
bytes(",".join(lst), "utf-8")
```

#### Key Exchange
| Algorithm | Required? |
| ------| --------|
| diffie-hellman-group1-sha1 | REQUIRED
| diffie-hellman-group14-sha1 | REQUIRED

##### Python Implementation for Key Exchange
```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

# Generate private keys for the client and server
client_private_key = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend()).generate_private_key()

# Generate public keys for the client and server
client_public_key = client_private_key.public_key()

# Exchange public keys
client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Calculate shared secret key
server_public_key = "GET server_public_key HERE"
client_shared_key = client_private_key.exchange(server_public_key)

# Hash shared secret key using SHA-1
client_key_material = HKDF(
    algorithm=hashes.SHA1(),
    length=32,
    salt=None,
    info=b"handshake data",
    backend=default_backend()
).derive(client_shared_key)
```

#### MAC
| Algorithm | Required? | Details |
| ---------- | ----------- | -------------|
| hmac-sha1  |  REQUIRED  |  HMAC-SHA1 (digest length = key length = 20)
| hmac-sha1-96  |  RECOMMENDED  |  first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
| hmac-md5  |  OPTIONAL  |  HMAC-MD5 (digest length = key length = 16)
| hmac-md5-96  |  OPTIONAL  |  first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
| none  |  OPTIONAL  |  no MAC; NOT RECOMMENDED

#### Encryption
| Algorithm  | Required? | Details |
| --------  | ------------------- | --------------------- |
| 3des-cbc | REQUIRED | three-key 3DES in CBC mode| 
| 3des-cbc | REQUIRED | three-key 3DES in CBC mode|
| blowfish-cbc | OPTIONAL | Blowfish in CBC mode
| twofish256-cbc | OPTIONAL | Twofish in CBC mode with a 256-bit key
| twofish-cbc | OPTIONAL | alias for "twofish256-cbc" (this is being retained for historical reasons)
| twofish192-cbc | OPTIONAL | Twofish with a 192-bit key
| twofish128-cbc | OPTIONAL | Twofish with a 128-bit key
| aes256-cbc | OPTIONAL | AES in CBC mode, with a 256-bit key
| aes192-cbc | OPTIONAL | AES with a 192-bit key
| aes128-cbc | RECOMMENDED | AES with a 128-bit key
| serpent256-cbc | OPTIONAL | Serpent in CBC mode, with a 256-bit key
| serpent192-cbc | OPTIONAL | Serpent with a 192-bit key
| serpent128-cbc | OPTIONAL | Serpent with a 128-bit key
| arcfour | OPTIONAL | the ARCFOUR stream cipher with a 128-bit key
| idea-cbc | OPTIONAL | IDEA in CBC mode
| cast128-cbc | OPTIONAL | CAST-128 in CBC mode
| none | OPTIONAL | no encryption; NOT RECOMMENDED

#### Compression
| Algorithm | Required? | Details |
| ------| ------| -----|
| none | REQUIRED | no compression
| zlib | OPTIONAL | ZLIB (LZ77) compression

## Generating the Keypairs
After exchanging SSH versions, the SSH client and SSH server perform a series of steps to establish a secure connection. Here's a general overview of the process:
1.  The client and server exchange keys to establish a secure connection. This involves the client generating a public/private key pair and sending the public key to the server. The server generates its own public/private key pair and sends the public key to the client. The client and server then use these keys to exchange messages and verify each other's identities.
2. The client sends a request to authenticate the connection to the server. This can be done using a variety of methods, such as password authentication or public key authentication.
3. If the authentication is successful, the server sends an acknowledgement message to the client and the secure connection is established.
4. Once the connection is established, the client can send commands to the server, and the server can execute those commands and send the results back to the client.

This process ensures that the connection between the client and server is secure and that only authorized users can access the server.

### Python Implementation
```python
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


def _generate_key_pair() -> tuple[bytes, bytes]:
	"""
	Method to generate a public/private rsa keypair
	Returns the bytes for the private key first, and the public key second
	"""
	key = rsa.generate_private_key(
		backend=crypto_default_backend(),
		public_exponent=65537,
		key_size=256
	)
	private_key = key.private_bytes(
		crypto_serialization.Encoding.OpenSSH,
		crypto_serialization.PrivateFormat.PKCS8,
		crypto_serialization.NoEncryption()
	)
	public_key = key.public_key().public_bytes(
		crypto_serialization.Encoding.OpenSSH,
		crypto_serialization.PublicFormat.OpenSSH
	)
	return private_key, public_key
```

## Further Reading
- Consult [RFC 4253 7.0](https://www.rfc-editor.org/rfc/rfc4253#section-7)


# References
- [RFC 4250](https://www.rfc-editor.org/rfc/rfc4250)
- [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251.html)
- [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252.html)
- [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html)
