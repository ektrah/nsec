# KeyBlobFormat Enum

Specifies a key BLOB format for use with [[Key|Key Class]] and
[[PublicKey|PublicKey Class]] objects.

    public enum KeyBlobFormat


## Members


#### Recommended:

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


#### Not Recommended:

RawPrivateKey
: The raw private key BLOB format.

RawPublicKey
: The raw public key BLOB format.

RawSymmetricKey
: The raw symmetric key BLOB format.


## See Also

* API Reference
    * [[Key Class]]
    * [[PublicKey Class]]
