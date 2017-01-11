# KeyAgreementAlgorithm Class

Represents a key agreement algorithm.

    public abstract class KeyAgreementAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **KeyAgreementAlgorithm**
        * X25519


## [TOC] Summary


## Properties


### PrivateKeySize

Get the size, in bytes, of a private key.

    public int PrivateKeySize { get; }

#### Property value

The size, in bytes, of a private key.


### PublicKeySize

Get the size, in bytes, of a public key.

    public int PublicKeySize { get; }

#### Property value

The size, in bytes, of a public key.


### SharedSecretSize

Get the size, in bytes, of the shared secret resulting from key agreement.

    public int SharedSecretSize { get; }

#### Property value

The size, in bytes, of the shared secret.


## Methods


### Agree(Key, PublicKey)

Creates a shared secret from a private and a public key.

    public SharedSecret Agree(
        Key key,
        PublicKey otherPartyPublicKey)

#### Parameters

key
: The private key to use to create the shared secret.

otherPartyPublicKey
: The public key from the other party to use to create the shared secret.

#### Return value

A new instance of the [[SharedSecret|SharedSecret Class]] class that represents
the shared secret created from `key` and `otherPartyPublicKey`.

#### Exceptions

ArgumentNullException
: `key` or `otherPartyPublicKey` is `null`.

ArgumentException
: `key.Algorithm` or `otherPartyPublicKey.Algorithm` is not the same object as
    the current [[KeyAgreementAlgorithm|KeyAgreementAlgorithm Class]] object.

CryptographicException
: Key agreement failed.

ObjectDisposedException
: `key` has been disposed.


### TryAgree(Key, PublicKey, out SharedSecret)

Attempts to create a shared secret from a private and a public key.

    public bool TryAgree(
        Key key,
        PublicKey otherPartyPublicKey,
        out SharedSecret result)

#### Parameters

key
: The private key to use to create the shared secret.

otherPartyPublicKey
: The public key from the other party to use to create the shared secret.

result
: When this method returns, contains a new instance of the
    [[SharedSecret|SharedSecret Class]] class that represents the shared
    secret, or `null` if key agreement failed.

#### Return value

`true` if key agreement succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` or `otherPartyPublicKey` is `null`.

ArgumentException
: `key.Algorithm` or `otherPartyPublicKey.Algorithm` is not the same object as
    the current [[KeyAgreementAlgorithm|KeyAgreementAlgorithm Class]] object.

ObjectDisposedException
: `key` has been disposed.


## See also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
    * [[PublicKey Class]]
    * [[SharedSecret Class]]
