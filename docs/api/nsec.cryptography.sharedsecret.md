# SharedSecret Class

Represents the output of a [[key agreement|KeyAgreementAlgorithm Class]] and the
input for [[key derivation|KeyDerivationAlgorithm Class]].

    public sealed class SharedSecret : IDisposable


## [TOC] Summary


## Properties


### Size

Gets the size, in bytes, of the shared secret.

    public int Size { get; }

#### Property value

The size, in bytes, of the shared secret.


## Methods


### Import(ReadOnlySpan<byte>)

Imports the specified shared secret.

    public static SharedSecret Import(
        ReadOnlySpan<byte> sharedSecret)

#### Parameters

sharedSecret
: The shared secret to import.

#### Return value

A new instance of the [[SharedSecret|SharedSecret Class]] class that represents
the imported shared secret.

#### Exceptions

ArgumentException
: The length of `sharedSecret` is greater than 128.


### Dispose()

Securely erases the shared secret and releases all resources used by the current
instance of the [[SharedSecret|SharedSecret Class]] class.

    public void Dispose()


## See also

* API Reference
    * [[KeyAgreementAlgorithm Class]]
    * [[KeyDerivationAlgorithm Class]]
