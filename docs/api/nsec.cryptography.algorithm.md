# Algorithm Class

Represents the base class from which all algorithm implementations derive.

    public abstract class Algorithm

The class has no public members.


## Inheritance Hierarchy

* **Algorithm**
    * [[AeadAlgorithm|AeadAlgorithm Class]]
        * Aes256Gcm
        * ChaCha20Poly1305
    * [[HashAlgorithm|HashAlgorithm Class]]
        * Blake2b
        * Sha256
        * Sha512
    * [[KeyAgreementAlgorithm|KeyAgreementAlgorithm Class]]
        * X25519
    * [[KeyDerivationAlgorithm|KeyDerivationAlgorithm Class]]
        * HkdfSha256
        * HkdfSha512
    * [[MacAlgorithm|MacAlgorithm Class]]
        * Blake2bMac
        * HmacSha256
        * HmacSha512
    * [[SignatureAlgorithm|SignatureAlgorithm Class]]
        * Ed25519
