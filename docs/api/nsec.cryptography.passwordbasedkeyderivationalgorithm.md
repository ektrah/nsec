# PasswordBasedKeyDerivationAlgorithm Class

...

    public abstract class PasswordBasedKeyDerivationAlgorithm : Algorithm

The [[PasswordBasedKeyDerivationAlgorithm|PasswordBasedKeyDerivationAlgorithm
Class]] class is intended for deriving keys from a secret value such as a
password. To derive keys from cryptographically strong input keying material,
use the [[KeyDerivationAlgorithm|KeyDerivationAlgorithm Class]] class.


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **PasswordBasedKeyDerivationAlgorithm**
        * Argon2id
        * Scrypt


## [TOC] Summary


## Static Methods


### Argon2id(in Argon2Parameters)

Gets the Argon2id algorithm with the specified parameters.

    public static Argon2id Argon2id(
        in Argon2Parameters parameters)

#### Parameters

parameters
: The parameters to use with the Argon2id algorithm.

!!! Note
    The parameters must be tuned according to the amount of memory and computing
    power available. Poor parameter choices can be harmful for security.

#### Return Value

An instance of the
[[PasswordBasedKeyDerivationAlgorithm|PasswordBasedKeyDerivationAlgorithm
Class]] class.

#### Exceptions

ArgumentException
: The specified parameters are out of the range of valid values.


### Scrypt(in ScryptParameters)

Gets the scrypt algorithm with the specified parameters.

    public static Scrypt Scrypt(
        in ScryptParameters parameters)

#### Parameters

parameters
: The parameters to use with the scrypt algorithm.

!!! Note
    The parameters must be tuned according to the amount of memory and computing
    power available. Poor parameter choices can be harmful for security.

#### Return Value

An instance of the
[[PasswordBasedKeyDerivationAlgorithm|PasswordBasedKeyDerivationAlgorithm
Class]] class.

#### Exceptions

ArgumentException
: The specified parameters are out of the range of valid values.


## Properties


### MaxCount

...

    public int MaxCount { get; }

#### Property Value

...


### SaltSize

...

    public int SaltSize { get; }

#### Property Value

...


## Methods


### DeriveBytes(ReadOnlySpan<byte>, ReadOnlySpan<byte>, int)

...

    public byte[] DeriveBytes(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int count)

!!! Note
    Depending on algorithm parameters, this method may require large amounts of
    memory. Callers should protect against a denial-of-service attack resulting
    from careless invocation.

#### Parameters

...

#### Return Value

...

#### Exceptions

...


### DeriveBytes(ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

...

    public void DeriveBytes(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        Span<byte> bytes)

!!! Note
    Depending on algorithm parameters, this method may require large amounts of
    memory. Callers should protect against a denial-of-service attack resulting
    from careless invocation.

#### Parameters

...

#### Return Value

...

#### Exceptions

...


### DeriveKey(ReadOnlySpan<byte>, ReadOnlySpan<byte>, Algorithm, in KeyCreationParameters creationParameters)

...

    public Key DeriveKey(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        Algorithm algorithm,
        in KeyCreationParameters creationParameters = default)

!!! Note
    Depending on algorithm parameters, this method may require large amounts of
    memory. Callers should protect against a denial-of-service attack resulting
    from careless invocation.

#### Parameters

...

#### Return Value

...

#### Exceptions

...


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Argon2Parameters Struct]]
    * [[ScryptParameters Struct]]
