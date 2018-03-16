# How to: Generate Nonces

It is critical for security that nonces are constructed in a way that the same
nonce is never used more than once to encrypt data with the same key. 

This is a hard problem if an application cannot keep track of the nonces it has
already generated, if an application is spread across multiple machines that use
the same key, or if more than one party in a group wants to encrypt data with
the same key.

Security protocols generally insist on generating nonces in their own way, which
is why NSec cannot provide a general, easy-to-use solution. This "how to" shows
how implement two specific solutions with NSec:

* [[TLS 1.2-style Nonces|How to: Generate Nonces#TLS 1.2-style Nonces]]
* [[TLS 1.3-style Nonces|How to: Generate Nonces#TLS 1.3-style Nonces]]

See [RFC 5116](https://tools.ietf.org/html/rfc5116) for recommendations and more
information on generating nonces.


## TLS 1.2-style Nonces

[RFC 5288](https://tools.ietf.org/html/rfc5288) recommends the following way to
generate nonces for use with AES-GCM in TLS. This style is the default in TLS
1.2.

TLS provides a secure channel between two a client and a server. Two keys are
used per channel: one for sending messages from the client to the server, and
one for sending messages from the server to the client. These are set up by the
TLS handshake, which also generates an Initialization Vector (IV) for each
direction.

The 12-byte nonce required by AES-GCM is formed as follows:

1. The 64-bit record sequence number is serialized as an 8-byte, big-endian
   value.

2. The serialized sequence number is appended to the 4-byte client IV.

The following C# example shows how to implemented this with NSec:

    {{Nonces: RFC 5288}}


## TLS 1.3-style Nonces

[RFC 7905](https://tools.ietf.org/html/rfc7905) recommends the following way to
generate nonces for use with ChaCha20-Poly1305 in TLS. This style is the default
in TLS 1.3.

As noted above, TLS provides a secure channel between two a client and a server.
Two keys are used per channel: one for sending messages from the client to the
server, and one for sending messages from the server to the client. These are
set up by the TLS handshake, which also generates an Initialization Vector (IV)
for each direction.

The 12-byte nonce required by ChaCha20-Poly1305 is formed as follows:

1. The 64-bit record sequence number is serialized as an 8-byte, big-endian
   value and padded on the left with four 0x00 bytes.

2. The padded sequence number is XORed with the 12-byte IV.

The following C# example shows how to implemented this with NSec:

    {{Nonces: RFC 7905}}


## References

* API Reference
    * [[AeadAlgorithm Class]]
    * [[Nonce Struct]]
* Specifications
    * [RFC 5116](https://tools.ietf.org/html/rfc5116) -- An Interface and Algorithms for Authenticated Encryption
    * [RFC 5288](https://tools.ietf.org/html/rfc5288) -- AES Galois Counter Mode (GCM) Cipher Suites for TLS
    * [RFC 7905](https://tools.ietf.org/html/rfc7905) -- ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
