# KeyBlobFormat Enum

Specifies a key BLOB format for use with [[Key|Key Class]] and
[[PublicKey|PublicKey Class]] objects.

    public enum KeyBlobFormat


## Members

NSecPrivateKey
: The NSec private key BLOB format.

NSecPublicKey
: The NSec public key BLOB format.

NSecSymmetricKey
: The NSec symmetric key BLOB format.

PkixPrivateKey
: The PKIX private key BLOB format.

PkixPrivateKeyText
: The PKIX private key BLOB format in textual encoding.

PkixPublicKey
: The PKIX public key BLOB format.

PkixPublicKeyText
: The PKIX public key BLOB format in textual encoding.

RawPrivateKey
: The raw private key BLOB format.

RawPublicKey
: The raw public key BLOB format.

RawSymmetricKey
: The raw symmetric key BLOB format.


## See also

* API Reference
    * [[Key Class]]
    * [[PublicKey Class]]
* Specifications
    * [I-D.ietf-curdle-pkix](https://tools.ietf.org/html/draft-ietf-curdle-pkix-03)
        -- Algorithm Identifiers for Ed25519, Ed25519ph, Ed448, Ed448ph, X25519
        and X448 for use in the Internet X.509 Public Key Infrastructure
    * [RFC 7468](https://tools.ietf.org/html/rfc7468) -- Textual Encodings of
        PKIX, PKCS, and CMS Structures
