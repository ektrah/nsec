# KeyAgreementAlgorithm Class

Represents a key agreement algorithm.

    public abstract class KeyAgreementAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **KeyAgreementAlgorithm**
        * X25519


## [TOC] Summary


## Static Properties


### X25519

Gets the X25519 key agreement algorithm.

    public static X25519 X25519 { get; }


## Properties


### PrivateKeySize

Gets the size of private keys.

    public int PrivateKeySize { get; }

#### Property Value

The private key size, in bytes.


### PublicKeySize

Gets the size of public keys.

    public int PublicKeySize { get; }

#### Property Value

The public key size, in bytes.


### SharedSecretSize

Gets the size of a shared secret resulting from key agreement.

    public int SharedSecretSize { get; }

#### Property Value

The shared secret size, in bytes.


## Methods


### Agree(Key, PublicKey, in SharedSecretCreationParameters)

Creates a shared secret from a private and a public key.

    public SharedSecret? Agree(
        Key key,
        PublicKey otherPartyPublicKey,
        in SharedSecretCreationParameters creationParameters = default)

#### Parameters

key
: The private key to use to create the shared secret.

otherPartyPublicKey
: The public key of the other party to use to create the shared secret.
    Key agreement fails if this is an invalid public key.

creationParameters
: A [[SharedSecretCreationParameters|SharedSecretCreationParameters Struct]]
    value that specifies advanced parameters for the creation of the
    [[SharedSecret|SharedSecret Class]] instance.

#### Return Value

A new instance of the [[SharedSecret|SharedSecret Class]] class that represents
the shared secret created from `key` and `otherPartyPublicKey`, or `null` if key
agreement fails.

#### Exceptions

ArgumentNullException
: `key` or `otherPartyPublicKey` is `null`.

ArgumentException
: `key.Algorithm` or `otherPartyPublicKey.Algorithm` is not the same object as
    the current [[KeyAgreementAlgorithm|KeyAgreementAlgorithm Class]] object.

ObjectDisposedException
: `key` has been disposed.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
    * [[PublicKey Class]]
    * [[SharedSecret Class]]
    * [[SharedSecretCreationParameters Struct]]
