# SharedSecret Class

Represents the output of a [[key agreement|KeyAgreementAlgorithm Class]] and the
input for [[key derivation|KeyDerivationAlgorithm Class]].

    public sealed class SharedSecret : IDisposable


## [TOC] Summary


## Properties


### Size

Gets the size of the shared secret.

    public int Size { get; }

#### Property Value

The size, in bytes, of the shared secret.


## Methods


### Dispose()

Securely erases the shared secret from memory and releases all resources used by
the current instance of the [[SharedSecret|SharedSecret Class]] class.

    public void Dispose()


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe.


## See Also

* API Reference
    * [[KeyAgreementAlgorithm Class]]
    * [[KeyDerivationAlgorithm Class]]
    * [[SharedSecretCreationParameters Struct]]
