# KeyDerivationAlgorithm Class

Represents a key derivation algorithm using keying material as input.

    public abstract class KeyDerivationAlgorithm : Algorithm

!!! Note
    The [[KeyDerivationAlgorithm|KeyDerivationAlgorithm Class]] class requires
    cryptographically suitable input keying material. To derive keys from
    passwords, use the
    [[PasswordBasedKeyDerivationAlgorithm|PasswordBasedKeyDerivationAlgorithm
    Class]] class.


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **KeyDerivationAlgorithm**
        * [[KeyDerivationAlgorithm2|KeyDerivationAlgorithm2 Class]]
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


### MaxSaltSize

Gets the maximum size of the salt used for key derivation.

    public int MaxSaltSize { get; }

#### Property Value

The maximum salt size, in bytes.


### MinSaltSize

Gets the minimum size of the salt used for key derivation.

    public int MinSaltSize { get; }

#### Property Value

The minimum salt size, in bytes.


## Methods


### DeriveBytes(SharedSecret or ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, int)

Derives the specified number of bytes from a shared secret or some other input keying material, using the specified
salt and context information.

    public byte[] DeriveBytes(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int count)

    public byte[] DeriveBytes(
        ReadOnlySpan<byte> inputKeyingMaterial,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int count)

#### Parameters

sharedSecret
: The [[SharedSecret|SharedSecret Class]] to derive the bytes from.

inputKeyingMaterial
: The input keying material to derive the bytes from.

salt
: Optional salt.

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
: `sharedSecret` is `null`.

ArgumentException
: `inputKeyingMaterial` is empty.

ArgumentException
: `salt.Length` is less than
    [[MinSaltSize|KeyDerivationAlgorithm Class#MinSaltSize]]
    or greater than
    [[MaxSaltSize|KeyDerivationAlgorithm Class#MaxSaltSize]].

ArgumentOutOfRangeException
: `count` is less than 0 or greater than
    [[MaxCount|KeyDerivationAlgorithm Class#MaxCount]].

ObjectDisposedException
: `sharedSecret` has been disposed.


### DeriveBytes(SharedSecret or ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with bytes derived from a shared secret or some other input keying material, using
the specified salt and context information.

    public void DeriveBytes(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Span<byte> bytes)

    public void DeriveBytes(
        ReadOnlySpan<byte> inputKeyingMaterial,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Span<byte> bytes)

#### Parameters

sharedSecret
: The [[SharedSecret|SharedSecret Class]] to derive the bytes from.

inputKeyingMaterial
: The input keying material to derive the bytes from.

salt
: Optional salt.

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
: `sharedSecret` is `null`.

ArgumentException
: `inputKeyingMaterial` is empty.

ArgumentException
: `salt.Length` is less than
    [[MinSaltSize|KeyDerivationAlgorithm Class#MinSaltSize]]
    or greater than
    [[MaxSaltSize|KeyDerivationAlgorithm Class#MaxSaltSize]].

ArgumentException
: `bytes.Length` is greater than
    [[MaxCount|KeyDerivationAlgorithm Class#MaxCount]].

ArgumentException
: `bytes` overlaps in memory with `salt` or `info`.

ObjectDisposedException
: `sharedSecret` has been disposed.


### DeriveKey(SharedSecret or ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Algorithm, in KeyCreationParameters)

Derives a key for the specified algorithm from a shared secret or some other input keying material, using the
specified salt and context information.

    public Key DeriveKey(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Algorithm algorithm,
        in KeyCreationParameters creationParameters = default)

    public Key DeriveKey(
        ReadOnlySpan<byte> inputKeyingMaterial,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Algorithm algorithm,
        in KeyCreationParameters creationParameters = default)

#### Parameters

sharedSecret
: The [[SharedSecret|SharedSecret Class]] to derive the key from.

inputKeyingMaterial
: The input keying material to derive the bytes from.

salt
: Optional salt.

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
: `inputKeyingMaterial` is empty.

ArgumentException
: `salt.Length` is less than
    [[MinSaltSize|KeyDerivationAlgorithm Class#MinSaltSize]]
    or greater than
    [[MaxSaltSize|KeyDerivationAlgorithm Class#MaxSaltSize]].

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
    * [[KeyDerivationAlgorithm2 Class]]
    * [[PasswordBasedKeyDerivationAlgorithm Class]]
    * [[SharedSecret Class]]
