# Algorithm Class

Represents the base class from which all algorithm implementations inherit.

    public abstract class Algorithm

The [[Algorithm|Algorithm Class]] class has no public members.


## Inheritance Hierarchy

* **Algorithm**
    * [[AeadAlgorithm|AeadAlgorithm Class]]
        * Aes256Gcm
        * ChaCha20Poly1305
    * [[HashAlgorithm|HashAlgorithm Class]]
        * Blake2
        * Sha256
        * Sha512
    * [[KeyAgreementAlgorithm|KeyAgreementAlgorithm Class]]
        * X25519
    * [[KeyDerivationAlgorithm|KeyDerivationAlgorithm Class]]
        * HkdfSha256
        * HkdfSha512
    * [[MacAlgorithm|MacAlgorithm Class]]
        * HmacSha256
        * HmacSha512
    * [[SignatureAlgorithm|SignatureAlgorithm Class]]
        * Ed25519
