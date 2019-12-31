# AeadAlgorithm Class

Represents an authenticated encryption with associated data (AEAD) algorithm.

    public abstract class AeadAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **AeadAlgorithm**
        * Aes256Gcm
        * ChaCha20Poly1305


## [TOC] Summary


## Static Properties


### Aes256Gcm

Gets the AES256-GCM AEAD algorithm.

    public static Aes256Gcm Aes256Gcm { get; }

#### Exceptions

PlatformNotSupportedException
: The platform does not support hardware-accelerated AES.

#### Remarks

The implementation of AES-GCM in NSec is hardware-accelerated and requires an
x64 processor with the AES-NI extension. The availability of this extension can
be determined at runtime using the static `IsSupported` property of the
`NSec.Cryptography.Aes256Gcm` class.


### ChaCha20Poly1305

Gets the ChaCha20-Poly1305 AEAD algorithm.

    public static ChaCha20Poly1305 ChaCha20Poly1305 { get; }


## Properties


### KeySize

Gets the size of the key used for encryption and decryption.

    public int KeySize { get; }

#### Property Value

The key size, in bytes.


### NonceSize

Gets the size of the nonce used for encryption and decryption.

    public int NonceSize { get; }

#### Property Value

The nonce size, in bytes.


### TagSize

Gets the size of the authentication tag.

    public int TagSize { get; }

#### Property Value

The authentication tag size, in bytes.


## Methods


### Encrypt(Key, in Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Encrypts the specified plaintext using the specified key, nonce, and associated
data, and returns the ciphertext, which includes an authentication tag, as an
array of bytes.

    public byte[] Encrypt(
        Key key,
        in Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext)

#### Parameters

key
: The [[Key|Key Class]] to use for encryption.
    This must be a cryptographically strong key as created by the
    [[RandomGenerator|RandomGenerator Class)]] class, not a password.

nonce
: The [[Nonce|Nonce Struct]] to use for encryption.
    The same nonce must not be used more than once to encrypt data with the
    specified key.

!!! Note
    Using the same nonce with the same key more than once leads to
    catastrophic loss of security.

: To prevent nonce reuse when encrypting multiple plaintexts with the same key,
    it is recommended to increment the previous nonce; a randomly generated
    nonce is not suitable. See [[Nonce Struct]] and [[How to: Generate
    Nonces]] for more information on generating nonces.

associatedData
: Optional additional data to be authenticated during decryption.

plaintext
: The data to encrypt.

#### Return Value

An array of bytes that contains the encrypted data and the authentication tag.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Size` is not equal to [[NonceSize|AeadAlgorithm Class#NonceSize]].

ArgumentException
: `plaintext.Length` plus [[TagSize|AeadAlgorithm Class#TagSize]] is greater
    than `int.MaxValue`.

ObjectDisposedException
: `key` has been disposed.


### Encrypt(Key, in Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Encrypts the specified plaintext using the specified key, nonce, and associated
data, and fills the specified span of bytes with the ciphertext, which includes
an authentication tag.

    public void Encrypt(
        Key key,
        in Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext)

#### Parameters

key
: The [[Key|Key Class]] to use for encryption.
    This must be a cryptographically strong key as created by the
    [[RandomGenerator|RandomGenerator Class)]] class, not a password.

nonce
: The [[Nonce|Nonce Struct]] to use for encryption.
    The same nonce must not be used more than once to encrypt data with the
    specified key.

!!! Note
    Using the same nonce with the same key more than once leads to
    catastrophic loss of security.

: To prevent nonce reuse when encrypting multiple plaintexts with the same key,
    it is recommended to increment the previous nonce; a randomly generated
    nonce is not suitable. See [[Nonce Struct]] and [[How to: Generate
    Nonces]] for more information on generating nonces.

associatedData
: Optional additional data to be authenticated during decryption.

plaintext
: The data to encrypt.

ciphertext
: The span to fill with the encrypted data and the authentication tag.
    The length of the span must be equal to `plaintext.Length` plus
    [[TagSize|AeadAlgorithm Class#TagSize]].
: `ciphertext` must not overlap in memory with `plaintext`, except if
    `ciphertext` and `plaintext` point at exactly the same memory location
    (in-place encryption).

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Size` is not equal to [[NonceSize|AeadAlgorithm Class#NonceSize]].

ArgumentException
: `ciphertext.Length` is not equal to `plaintext.Length` plus
    [[TagSize|AeadAlgorithm Class#TagSize]].

ArgumentException
: `ciphertext` overlaps in memory with `plaintext`.

ObjectDisposedException
: `key` has been disposed.


### Decrypt(Key, in Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>, out byte[])

Decrypts and authenticates the specified ciphertext using the specified key,
nonce, and associated data. If successful, returns the decrypted plaintext as an
array of bytes.

    public bool Decrypt(
        Key key,
        in Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        out byte[] plaintext)

#### Parameters

key
: The [[Key|Key Class]] to use for decryption.
    Authentication fails if this is not the same key that was used for
    encryption.

nonce
: The [[Nonce|Nonce Struct]] to use for decryption.
    Authentication fails if this is not the same nonce that was used for
    encryption.

associatedData
: Optional additional data to authenticate.
    Authentication fails if this is not the same additional data that was used
    for encryption.

ciphertext
: The encrypted data to authenticate and decrypt.
    Authentication fails if the integrity of the data was compromised.

plaintext
: When this method returns, contains an array of bytes that contains the
    decrypted and authenticated data, or `null` if authentication fails.

#### Return Value

`true` if decryption and authentication succeed; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ObjectDisposedException
: `key` has been disposed.


### Decrypt(Key, in Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Decrypts and authenticates the specified ciphertext using the specified key,
nonce, and associated data. If successful, fills the specified span of bytes
with the decrypted plaintext.

    public bool Decrypt(
        Key key,
        in Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext)

#### Parameters

key
: The [[Key|Key Class]] to use for decryption.
    Authentication fails if this is not the same key that was used for
    encryption.

nonce
: The [[Nonce|Nonce Struct]] to use for decryption.
    Authentication fails if this is not the same nonce that was used for
    encryption.

associatedData
: Optional additional data to authenticate.
    Authentication fails if this is not the same additional data that was used
    for encryption.

ciphertext
: The encrypted data to authenticate and decrypt.
    Authentication fails if the integrity of the data was compromised.

plaintext
: The span to fill with the decrypted and authenticated data.
    The length of the span must be equal to `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]].
: `plaintext` must not overlap in memory with `ciphertext`, except if
    `plaintext` and `ciphertext` point at exactly the same memory location
    (in-place decryption).

#### Return Value

`true` if decryption and authentication succeed; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `plaintext.Length` is not equal to `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]].

ArgumentException
: `plaintext` overlaps in memory with `ciphertext`.

ObjectDisposedException
: `key` has been disposed.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
    * [[Nonce Struct]]
* Working with NSec
    * [[How to: Generate Nonces]]
