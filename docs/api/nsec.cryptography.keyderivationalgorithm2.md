# KeyDerivationAlgorithm2 Class

Represents a key derivation algorithm using keying material as input.

    public abstract class KeyDerivationAlgorithm2 : KeyDerivationAlgorithm

This type provides an "extract-then-expand" interface for deriving keys from
keying material, where the algorithm logically consists of two stages: The first
stage takes the input keying material and "extracts" from it a fixed-length
pseudorandom key. The second stage "expands" the pseudorandom key to the desired
length. In some applications, the input may already be a good pseudorandom key;
in these cases, the "extract" stage is not necessary, and the "expand" part can
be used alone.

!!! Note
    The [[KeyDerivationAlgorithm2|KeyDerivationAlgorithm2 Class]] class requires
    cryptographically suitable input keying material. To derive keys from
    passwords, use the
    [[PasswordBasedKeyDerivationAlgorithm|PasswordBasedKeyDerivationAlgorithm
    Class]] class.


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * [[KeyDerivationAlgorithm|KeyDerivationAlgorithm Class]]
        * **KeyDerivationAlgorithm2**
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


### PseudorandomKeySize

Gets the size of the pseudorandom key.

    public int MaxCount { get; }

#### Property Value

The size, in bytes, of the pseudorandom key.


## Methods


### Extract(SharedSecret or ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Extracts a fixed-length pseudorandom key from a shared secret or some other
input keying material, using the specified salt

    public byte[] Extract(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt)

    public byte[] Extract(
        ReadOnlySpan<byte> inputKeyingMaterial,
        ReadOnlySpan<byte> salt)

#### Parameters

sharedSecret
: The [[SharedSecret|SharedSecret Class]] to extract the pseudorandom key from.

inputKeyingMaterial
: The input keying material to extract the pseudorandom key from.

salt
: Optional salt.

#### Return Value

An array of bytes that contains the extracted pseudorandom key.

#### Exceptions

ArgumentNullException
: `sharedSecret` is `null`.

ArgumentException
: `salt.Length` is less than
    [[MinSaltSize|KeyDerivationAlgorithm2 Class#MinSaltSize]]
    or greater than
    [[MaxSaltSize|KeyDerivationAlgorithm2 Class#MaxSaltSize]].

ObjectDisposedException
: `sharedSecret` has been disposed.


### Extract(SharedSecret or ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with a fixed-length pseudorandom key extracted
from a shared secret or some other input keying material, using the specified
salt.

    public void Extract(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        Span<byte> pseudorandomKey)

    public void Extract(
        ReadOnlySpan<byte> inputKeyingMaterial,
        ReadOnlySpan<byte> salt,
        Span<byte> pseudorandomKey)

#### Parameters

sharedSecret
: The [[SharedSecret|SharedSecret Class]] to extract the pseudorandom key from.

inputKeyingMaterial
: The input keying material to extract the pseudorandom key from.

salt
: Optional salt.

pseudorandomKey
: The span to fill with the pseudorandom key.

#### Exceptions

ArgumentNullException
: `sharedSecret` is `null`.

ArgumentException
: `salt.Length` is less than
    [[MinSaltSize|KeyDerivationAlgorithm2 Class#MinSaltSize]]
    or greater than
    [[MaxSaltSize|KeyDerivationAlgorithm2 Class#MaxSaltSize]].

ArgumentException
: `pseudorandomKey.Length` is not equal to
    [[PseudorandomKeySize|KeyDerivationAlgorithm2 Class#PseudorandomKeySize]].

ObjectDisposedException
: `sharedSecret` has been disposed.


### Expand(ReadOnlySpan<byte>, ReadOnlySpan<byte>, int count)

Expands a pseudorandom key to the specified number of bytes, using the specified
context information.

    public byte[] Expand(
        ReadOnlySpan<byte> pseudorandomKey,
        ReadOnlySpan<byte> info,
        int count)

#### Parameters

pseudorandomKey
: The pseudorandom key to expand.

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
: The number of bytes to expand from the pseudorandom key.

#### Return Value

An array of bytes that contains the expanded bytes.

#### Exceptions

ArgumentException
: `pseudorandomKey.Length` is less than
    [[PseudorandomKeySize|KeyDerivationAlgorithm2 Class#PseudorandomKeySize]].

ArgumentOutOfRangeException
: `count` is less than 0 or greater than
    [[MaxCount|KeyDerivationAlgorithm2 Class#MaxCount]].


### Expand(ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with bytes expanded from a pseudorandom key,
using the specified context information.

    public void Expand(
        ReadOnlySpan<byte> pseudorandomKey,
        ReadOnlySpan<byte> info,
        Span<byte> bytes)

#### Parameters

pseudorandomKey
: The pseudorandom key to expand.

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
: The span to fill with bytes expanded from the pseudorandom key.
    `bytes` must not overlap in memory with `pseudorandomKey` or `info`.

#### Exceptions

ArgumentException
: `pseudorandomKey.Length` is less than
    [[PseudorandomKeySize|KeyDerivationAlgorithm2 Class#PseudorandomKeySize]].

ArgumentException
: `bytes.Length` is greater than
    [[MaxCount|KeyDerivationAlgorithm2 Class#MaxCount]].

ArgumentException
: `bytes` overlaps in memory with `pseudorandomKey` or `info`.


### ExpandKey(ReadOnlySpan<byte>, ReadOnlySpan<byte>, Algorithm, in KeyCreationParameters)

Creates a key for the specified algorithm from a pseudorandom key, using the
specified context information.

    public Key ExpandKey(
        ReadOnlySpan<byte> pseudorandomKey,
        ReadOnlySpan<byte> info,
        Algorithm algorithm,
        in KeyCreationParameters creationParameters = default)

#### Parameters

pseudorandomKey
: The pseudorandom key to expand.

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

ArgumentException
: `pseudorandomKey.Length` is less than
    [[PseudorandomKeySize|KeyDerivationAlgorithm2 Class#PseudorandomKeySize]].

ArgumentNullException
: `algorithm` is `null`.

NotSupportedException
: The specified algorithm does not support keys derived from a shared secret.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[KeyDerivationAlgorithm Class]]
    * [[PasswordBasedKeyDerivationAlgorithm Class]]
    * [[SharedSecret Class]]
