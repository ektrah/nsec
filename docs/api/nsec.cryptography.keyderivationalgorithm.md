# KeyDerivationAlgorithm Class

Represents a key derivation algorithm.

    public abstract class KeyDerivationAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **KeyDerivationAlgorithm**
        * HkdfSha256
        * HkdfSha512


## [TOC] Summary


## Static Properties


### HkdfSha256

Gets the HKDF-SHA256 key derivation algorithm.

    public static HkdfSha256 HkdfSha256 { get; }


### HkdfSha512

Gets the HKDF-SHA512 key derivation algorithm.

    public static HkdfSha512 HkdfSha512 { get; }



## Properties


### MaxCount

Gets the maximum number of bytes that can be derived from a shared secret.

    public int MaxCount { get; }

#### Property Value

The maximum size, in bytes, of the key derivation output.


### SupportsSalt

Gets a value that indicates whether the algorithm supports the use of salt.

    public bool SupportsSalt { get; }

#### Property Value

`true` if the algorithm supports the use of salt; otherwise, `false`.


## Methods


### DeriveBytes(SharedSecret, ReadOnlySpan<byte>, ReadOnlySpan<byte>, int)

Derives the specified number of bytes from a shared secret, using the specified
salt and context information.

    public byte[] DeriveBytes(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int count)

#### Parameters

sharedSecret
: The [[SharedSecret|SharedSecret Class]] to derive the bytes from.

salt
: Optional salt.
    Must be empty if the algorithm does not support the use of salt.

info
: Context and application specific information. This should be used to ensure
    that the derived bytes are adequately bound to the context of the key
    agreement.

!!! Note
    Inadequate context information might lead to subtle vulnerabilities.

: To bind the derived bytes to the context, `info` may need to include the
    identifiers of the entities involved, their public keys, protocol-related
    information, and parameter choices. 

count
: The number of bytes to derive.

#### Return Value

An array of bytes that contains the derived bytes.

#### Exceptions

ArgumentNullException
: `sharedSecret` is `null`

ArgumentException
: [[SupportsSalt|KeyDerivationAlgorithm Class#SupportsSalt]] is `false` but
    `salt` is not empty.

ArgumentOutOfRangeException
: `count` is less than 0 or greater than
    [[MaxCount|KeyDerivationAlgorithm Class#MaxCount]].

ObjectDisposedException
: `sharedSecret` has been disposed.


### DeriveBytes(SharedSecret, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with bytes derived from a shared secret, using
the specified salt and context information.

    public void DeriveBytes(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Span<byte> bytes)

#### Parameters

sharedSecret
: The [[SharedSecret|SharedSecret Class]] to derive the bytes from.

salt
: Optional salt.
    Must be empty if the algorithm does not support the use of salt.

info
: Context and application specific information. This should be used to ensure
    that the derived bytes are adequately bound to the context of the key
    agreement.

!!! Note
    Inadequate context information might lead to subtle vulnerabilities.

: To bind the derived bytes to the context, `info` may need to include the
    identifiers of the entities involved, their public keys, protocol-related
    information, and parameter choices. 

bytes
: The span to fill with bytes derived from the shared secret.
    `bytes` must not overlap in memory with `salt` or `info`.

#### Exceptions

ArgumentNullException
: `sharedSecret` is `null`

ArgumentException
: [[SupportsSalt|KeyDerivationAlgorithm Class#SupportsSalt]] is `false` but
    `salt` is not empty.

ArgumentException
: `bytes.Length` is greater than
    [[MaxCount|KeyDerivationAlgorithm Class#MaxCount]].

ArgumentException
: `bytes` overlaps in memory with `salt` or `info`.

ObjectDisposedException
: `sharedSecret` has been disposed.


### DeriveKey(SharedSecret, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Algorithm, in KeyCreationParameters)

Derives a key for the specified algorithm from a shared secret, using the
specified salt and context information.

    public Key DeriveKey(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Algorithm algorithm,
        in KeyCreationParameters creationParameters = default)

#### Parameters

sharedSecret
: The [[SharedSecret|SharedSecret Class]] to derive the key from.

salt
: Optional salt.
    Must be empty if the algorithm does not support the use of salt.

info
: Context and application specific information. This should be used to ensure
    that the derived key is adequately bound to the context of the key
    agreement.

!!! Note
    Inadequate context information might lead to subtle vulnerabilities.

: To bind the derived key to the context, `info` may need to include the
    identifiers of the entities involved, their public keys, protocol-related
    information, and parameter choices. 

algorithm
: The algorithm for the new key.

creationParameters
: A [[KeyCreationParameters|KeyCreationParameters Struct]] value that specifies
    advanced parameters for the creation of the [[Key|Key Class]] instance.

#### Return Value

A new instance of the [[Key|Key Class]] class that represents the derived key.

#### Exceptions

ArgumentNullException
: `sharedSecret` or `algorithm` is `null`.

ArgumentException
: [[SupportsSalt|KeyDerivationAlgorithm Class#SupportsSalt]] is `false` but
    `salt` is not empty.

NotSupportedException
: The specified algorithm does not support keys derived from a shared secret.

ObjectDisposedException
: `sharedSecret` has been disposed.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[SharedSecret Class]]
