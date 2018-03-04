# KeyDerivationAlgorithm Class

Represents a key derivation algorithm.

    public abstract class KeyDerivationAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **KeyDerivationAlgorithm**
        * HkdfSha256
        * HkdfSha512


## [TOC] Summary


## Properties


### MaxOutputSize

Gets the maximum size, in bytes, of the key derivation output.

    public int MaxOutputSize { get; }

#### Property Value

The maximum size, in bytes, of the key derivation output.


### SupportsSalt

Gets a value that indicates whether the algorithm supports the use of salt.

    public bool SupportsSalt { get; }

#### Property Value

`true` if the algorithm supports the use of salt; otherwise, `false`.


## Methods


### DeriveBytes(SharedSecret, ReadOnlySpan<byte>, ReadOnlySpan<byte>, int)

Derives the specified number of bytes from a shared secret.

    public byte[] DeriveBytes(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int count)

#### Parameters

sharedSecret
: The shared secret to derive bytes from.

salt
: Optional salt.

info
: Optional context and application specific information.

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
    [[MaxOutputSize|KeyDerivationAlgorithm Class#MaxOutputSize]].

ObjectDisposedException
: `sharedSecret` has been disposed.


### DeriveBytes(SharedSecret, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with bytes derived from a shared secret.

    public void DeriveBytes(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Span<byte> bytes)

#### Parameters

sharedSecret
: The shared secret to derive bytes from.

salt
: Optional salt.

info
: Optional context and application specific information.

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
    [[MaxOutputSize|KeyDerivationAlgorithm Class#MaxOutputSize]].

ArgumentException
: `bytes` overlaps in memory with `salt` or `info`.

ObjectDisposedException
: `sharedSecret` has been disposed.


### DeriveKey(SharedSecret, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Algorithm, KeyExportPolicies)

Derives a key for the specified algorithm from a shared secret.

    public Key DeriveKey(
        SharedSecret sharedSecret,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Algorithm algorithm,
        KeyExportPolicies exportPolicy = KeyExportPolicies.None)

#### Parameters

sharedSecret
: The shared secret to derive a key from.

salt
: Optional salt.

info
: Optional context and application specific information.

algorithm
: The algorithm for the new key.

exportPolicy
: A bitwise combination of [[KeyExportPolicies|KeyExportPolicies Enum]] values
    that specifies the export policy for the derived key.
    
#### Return Value

A new instance of the [[Key|Key Class]] class that represents the derived key.

#### Exceptions

ArgumentNullException
: `sharedSecret` or `algorithm` is `null`.

ArgumentException
: [[SupportsSalt|KeyDerivationAlgorithm Class#SupportsSalt]] is `false` but
    `salt` is not empty.

NotSupportedException
: The specified algorithm does not support key derivation.

ObjectDisposedException
: `sharedSecret` has been disposed.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods give the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[SharedSecret Class]]
