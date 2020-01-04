# SignatureAlgorithm Class

Represents a digital signature algorithm.

    public abstract class SignatureAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **SignatureAlgorithm**
        * Ed25519


## [TOC] Summary


## Static Properties


### Ed25519

Gets the Ed25519 signature algorithm.

    public static Ed25519 Ed25519 { get; }


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


### SignatureSize

Gets the size of a signature.

    public int SignatureSize { get; }

#### Property Value

The signature size, in bytes.


### SeedSize

Gets the size of a seed.

    public int SeedSize { get; }

#### Property Value

The seed size, in bytes.


## Methods


### Sign(Key, ReadOnlySpan<byte>)

Signs the specified input data using the specified key and returns the signature
as an array of bytes.

    public byte[] Sign(
        Key key,
        ReadOnlySpan<byte> data)

#### Parameters

key
: The [[Key|Key Class]] to use for signing.

data
: The data to sign.

#### Return Value

The signature for the data.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[SignatureAlgorithm|SignatureAlgorithm Class]] object.

ObjectDisposedException
: `key` has been disposed.


### Sign(Key, ReadOnlySpan<byte>, Span<byte>)

Signs the specified input data using the specified key and fills the specified
span of bytes with the signature.

    public void Sign(
        Key key,
        ReadOnlySpan<byte> data,
        Span<byte> signature)

#### Parameters

key
: The [[Key|Key Class]] to use for signing.

data
: The data to sign.

signature
: The span to fill with the signature for the data.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[SignatureAlgorithm|SignatureAlgorithm Class]] object.

ArgumentException
: `signature.Length` is not equal to
    [[SignatureSize|SignatureAlgorithm Class#SignatureSize]].

ObjectDisposedException
: `key` has been disposed.


### Verify(PublicKey, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Verifies specified input data using the specified public key and signature.

    public bool Verify(
        PublicKey publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)

#### Parameters

publicKey
: The [[PublicKey|PublicKey Class]] to use for verification.
    Verification fails if this is not the public key for the private key used
    when signing the data.

data
: The data to verify.
    Verification fails if the integrity of the data was compromised.

signature
: The signature of the data to verify.

#### Return Value

`true` if verification succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `publicKey` is `null`.

ArgumentException
: `publicKey.Algorithm` is not the same object as the current
    [[SignatureAlgorithm|SignatureAlgorithm Class]] object.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
    * [[PublicKey Class]]
