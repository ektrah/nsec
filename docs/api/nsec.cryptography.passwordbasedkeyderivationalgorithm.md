# PasswordBasedKeyDerivationAlgorithm Class

Represents a key derivation algorithm using passwords as input.

    public abstract class PasswordBasedKeyDerivationAlgorithm : Algorithm


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
: An [[Argon2Parameters|Argon2Parameters Struct]] value that specifies the
    parameters to use with the Argon2id algorithm.

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
     See the [[Argon2Parameters|Argon2Parameters Struct]] struct for details.


### Scrypt(in ScryptParameters)

Gets the scrypt algorithm with the specified parameters.

    public static Scrypt Scrypt(
        in ScryptParameters parameters)

#### Parameters

parameters
: A [[ScryptParameters|ScryptParameters Struct]] value that specifies the
    parameters to use with the scrypt algorithm.

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
     See the [[ScryptParameters|ScryptParameters Struct]] struct for details.


## Properties


### MaxCount

Gets the maximum number of bytes that can be derived from a password.

    public int MaxCount { get; }

#### Property Value

The maximum size, in bytes, of the key derivation output.


### SaltSize

Gets the size of the salt used for key derivation.

    public int SaltSize { get; }

#### Property Value

The salt size, in bytes.


## Methods


### DeriveBytes(ReadOnlySpan<byte>, ReadOnlySpan<byte>, int)

Derives the specified number of bytes from a password, using the specified salt.

    public byte[] DeriveBytes(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int count)

!!! Note
    Depending on algorithm parameters, this method may require large amounts of
    memory. Callers should protect against a denial-of-service attack resulting
    from careless invocation.

#### Parameters

password
: The password to derive the bytes from.

salt
: The salt.

count
: The number of bytes to derive.

#### Return Value

An array of bytes that contains the derived bytes.

#### Exceptions

ArgumentException
: `salt.Length` is not equal to [[SaltSize|PasswordBasedKeyDerivationAlgorithm
    Class#SaltSize]].

ArgumentOutOfRangeException
: `count` is less than 0 or greater than
    [[MaxCount|PasswordBasedKeyDerivationAlgorithm Class#MaxCount]].

CryptographicException
: The computation of the derived bytes failed, usually because the operating
    system refused to allocate the amount of requested memory.


### DeriveBytes(ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with bytes derived from a password, using the
specified salt.

    public void DeriveBytes(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        Span<byte> bytes)

!!! Note
    Depending on algorithm parameters, this method may require large amounts of
    memory. Callers should protect against a denial-of-service attack resulting
    from careless invocation.

#### Parameters

password
: The password to derive the bytes from.

salt
: The salt.

bytes
: The span to fill with bytes derived from the password.

#### Exceptions

ArgumentException
: `salt.Length` is not equal to [[SaltSize|PasswordBasedKeyDerivationAlgorithm
    Class#SaltSize]].

ArgumentException
: `bytes.Length` is greater than
    [[MaxCount|PasswordBasedKeyDerivationAlgorithm Class#MaxCount]].

CryptographicException
: The computation of the derived bytes failed, usually because the operating
    system refused to allocate the amount of requested memory.


### DeriveKey(ReadOnlySpan<byte>, ReadOnlySpan<byte>, Algorithm, in KeyCreationParameters creationParameters)

Derives a key for the specified algorithm from a password, using the specified
salt.

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

password
: The password to derive the key from.

salt
: The salt.

algorithm
: The algorithm for the new key.

creationParameters
: A [[KeyCreationParameters|KeyCreationParameters Struct]] value that specifies
    advanced parameters for the creation of the [[Key|Key Class]] instance.

#### Return Value

A new instance of the [[Key|Key Class]] class that represents the derived key.

#### Exceptions

ArgumentException
: `salt.Length` is not equal to [[SaltSize|PasswordBasedKeyDerivationAlgorithm
    Class#SaltSize]].

ArgumentNullException
: `algorithm` is `null`.

NotSupportedException
: The specified algorithm does not support keys derived from a password.

CryptographicException
: The computation of the derived key failed, usually because the operating
    system refused to allocate the amount of requested memory.


## Remarks

The [[PasswordBasedKeyDerivationAlgorithm|PasswordBasedKeyDerivationAlgorithm
Class]] class is intended for deriving keys from passwords. To derive keys from
cryptographically strong input keying material, use the
[[KeyDerivationAlgorithm|KeyDerivationAlgorithm Class]] class.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[Argon2Parameters Struct]]
    * [[KeyDerivationAlgorithm Class]]
    * [[ScryptParameters Struct]]
