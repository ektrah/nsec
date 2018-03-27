# How to: Generate Nonces

For the security of the AEAD algorithms in NSec, it is critical that nonces are
constructed in a way that the same nonce is never used more than once to encrypt
data with the same key. 

Security protocols generally need nonces generated in their own way, which is
why NSec doesn't provide a general, easy-to-use solution. This "how to" shows
how two specific solutions can be implemented with NSec:

* [[TLS 1.2-style Nonces|How to: Generate Nonces#TLS 1.2-style Nonces]]
* [[TLS 1.3-style Nonces|How to: Generate Nonces#TLS 1.3-style Nonces]]

See RFC 5116 for recommendations and more information on generating nonces.


## TLS 1.2-style Nonces

RFC 5288 recommends the following way to generate nonces for use with AES-GCM in
Transport Layer Security (TLS). This style is the default in TLS version 1.2.

TLS provides a secure channel between two a client and a server. Two keys are
used per channel: one for sending messages from the client to the server, and
one for sending messages from the server to the client. These are set up by the
TLS handshake, which also outputs two Initialization Vectors (IV), one for each
direction.

The 12-byte nonce required by AES-GCM is formed as follows:

1. The 64-bit record sequence number for the direction is serialized as an
   8-byte, big-endian value.

2. The serialized sequence number is appended to the 4-byte IV for the
   direction.

The following C# example shows how to implement this with NSec:

    {{Nonces: RFC 5288}}


## TLS 1.3-style Nonces

RFC 7905 recommends the following way to generate nonces for use with
ChaCha20-Poly1305 in Transport Layer Security (TLS). This style is the default
in TLS version 1.3.

As noted above, TLS provides a secure channel between two a client and a server.
Two keys are used per channel: one for sending messages from the client to the
server, and one for sending messages from the server to the client. These are
set up by the TLS handshake, which also outputs two Initialization Vectors (IV),
one for each direction.

The 12-byte nonce required by ChaCha20-Poly1305 is formed as follows:

1. The 64-bit record sequence number for the direction is serialized as an
   8-byte, big-endian value and padded on the left with four 0x00 bytes.

2. The padded sequence number is XORed with the 12-byte IV for the direction.

The following C# example shows how to implement this with NSec:

    {{Nonces: RFC 7905}}


## References

* API Reference
    * [[AeadAlgorithm Class]]
    * [[Nonce Struct]]
* Specifications
    * [RFC 5116](https://tools.ietf.org/html/rfc5116) -- An Interface and Algorithms for Authenticated Encryption
    * [RFC 5288](https://tools.ietf.org/html/rfc5288) -- AES Galois Counter Mode (GCM) Cipher Suites for TLS
    * [RFC 7905](https://tools.ietf.org/html/rfc7905) -- ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
