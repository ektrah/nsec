# HashAlgorithm Class

Represents a cryptographic hash algorithm.

    public abstract class HashAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **HashAlgorithm**
        * Blake2b
        * Sha256
        * Sha512


## [TOC] Summary


## Static Properties


### Blake2b

Gets the unkeyed BLAKE2b algorithm.

    public static Blake2b Blake2b { get; }


### Sha256

Gets the SHA-256 hash algorithm.

    public static Sha256 Sha256 { get; }


### Sha512

Gets the SHA-512 hash algorithm.

    public static Sha512 Sha512 { get; }


## Properties


### HashSize

Gets the hash size, in bytes.

    public int HashSize { get; }

#### Property Value

The hash size, in bytes.


## Methods


### Hash(ReadOnlySpan<byte>)

Computes a hash for the specified input data and returns it as an array of
bytes.

    public byte[] Hash(
        ReadOnlySpan<byte> data)

#### Parameters

data
: The data to hash.

#### Return Value

The computed hash.


### Hash(ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with a hash for the specified input data.

    public void Hash(
        ReadOnlySpan<byte> data,
        Span<byte> hash)

#### Parameters

data
: The data to hash.

hash
: The span to fill with the computed hash.

#### Exceptions

ArgumentException
: `hash.Length` is not equal to [[HashSize|HashAlgorithm Class#HashSize]].


### TryVerify(ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Attempts to verify the hash for the specified input data.

    public bool TryVerify(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> hash)

#### Parameters

data
: The data to be verified.

hash
: The hash to be verified.

#### Return Value

`true` if verification succeeds; otherwise, `false`.


### Verify(ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Verifies the hash for the specified input data.

    public void Verify(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> hash)

#### Parameters

data
: The data to be verified.

hash
: The hash to be verified.

#### Exceptions

CryptographicException
: Verification failed.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[IncrementalHash Struct]]
