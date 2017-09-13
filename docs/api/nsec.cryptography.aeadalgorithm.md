# AeadAlgorithm Class

Represents an authenticated encryption with associated data (AEAD) algorithm.

    public abstract class AeadAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **AeadAlgorithm**
        * Aes256Gcm
        * ChaCha20Poly1305


## [TOC] Summary


## Properties


### KeySize

Gets the key size, in bytes.

    public int KeySize { get; }

#### Property Value

The key size, in bytes.


### NonceSize

Gets the nonce size, in bytes.

    public int NonceSize { get; }

#### Property Value

The nonce size, in bytes.


### TagSize

Gets the authentication tag size, in bytes.

    public int TagSize { get; }

#### Property Value

The authentication tag size, in bytes.


## Methods


### Decrypt(Key, Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Decrypts and authenticates the specified data using the specified key and
returns the result as an array of bytes.

    public byte[] Decrypt(
        Key key,
        Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext)

#### Parameters

key
: The key to use for decryption.

nonce
: The nonce to use for decryption.
    This must be the same nonce as used for encryption.

associatedData
: Optional additional data to be authenticated.
    This must be the same additional data as used for encryption.

ciphertext
: The encrypted data to be decrypted and authenticated.

#### Return Value

An array of bytes that contains the decrypted and authenticated data.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Size` is not equal to [[NonceSize|AeadAlgorithm Class#NonceSize]].

CryptographicException
: Authentication failed.

ObjectDisposedException
: `key` has been disposed.


### Decrypt(Key, Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Decrypts and authenticates the specified data using the specified key and fills
the specified span of bytes with the result.

    public void Decrypt(
        Key key,
        Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext)

#### Parameters

key
: The key to use for decryption.

nonce
: The nonce to use for decryption.
    This must be the same nonce as used for encryption.

associatedData
: Optional additional data to be authenticated.
    This must be the same additional data as used for encryption.

ciphertext
: The encrypted data to be decrypted and authenticated.

plaintext
: The span to fill with the decrypted and authenticated data.
    The length of the span must be equal to `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]]. `plaintext` must not overlap with
    `ciphertext`, except if `plaintext` and `ciphertext` point exactly at the
    same memory location (in-place decryption).

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Size` is not equal to [[NonceSize|AeadAlgorithm Class#NonceSize]].

ArgumentException
: `plaintext.Length` is not equal to `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]].

ArgumentException
: `plaintext` overlaps with `ciphertext`.

CryptographicException
: `ciphertext.Length` is less than
    [[TagSize|AeadAlgorithm Class#TagSize]].

CryptographicException
: Authentication failed.

ObjectDisposedException
: `key` has been disposed.


### Encrypt(Key, Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Encrypts the specified data using the specified key and returns the result,
which includes an authentication tag, as an array of bytes.

    public byte[] Encrypt(
        Key key,
        Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext)

#### Parameters

key
: The key to use for encryption.

nonce
: The nonce to use for encryption.
    The nonce must not be used more than once to encrypt data with the specified
    key.

!!! Note
    Using the same nonce with the same key more than once leads to catastrophic
    loss of security.

associatedData
: Optional additional data to be authenticated during decryption.

plaintext
: The data to be encrypted.

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
: `plaintext.Length` plus [[TagSize|AeadAlgorithm Class#TagSize]]
    is greater than `Int32.MaxValue`.

ObjectDisposedException
: `key` has been disposed.


### Encrypt(Key, Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Encrypts the specified data using the specified key and fills the specified
span of bytes with the result, which includes an authentication tag.

    public void Encrypt(
        Key key,
        Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext)

#### Parameters

key
: The key to use for encryption.

nonce
: The nonce to use for encryption.
    The nonce must not be used more than once to encrypt data with the specified
    key.

!!! Note
    Using the same nonce with the same key more than once leads to catastrophic
    loss of security.

associatedData
: Optional additional data to be authenticated during decryption.

plaintext
: The data to be encrypted.

ciphertext
: The span to fill with the encrypted data and the authentication tag.
    The length of the span must be equal to `plaintext.Length` plus
    [[TagSize|AeadAlgorithm Class#TagSize]]. `ciphertext` must not overlap with
    `plaintext`, except if `ciphertext` and `plaintext` point exactly at the
    same memory location (in-place encryption).

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Size` is not equal to [[NonceSize|AeadAlgorithm Class#NonceSize]].

ArgumentException
: `plaintext.Length` plus [[TagSize|AeadAlgorithm Class#TagSize]]
    is greater than `Int32.MaxValue`.

ArgumentException
: `ciphertext.Length` is not equal to `plaintext.Length` plus
    [[TagSize|AeadAlgorithm Class#TagSize]].

ArgumentException
: `ciphertext` overlaps with `plaintext`.

ObjectDisposedException
: `key` has been disposed.


### TryDecrypt(Key, Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>, out byte[])

Attempts to decrypt and authenticate the specified data using the specified key.
If successful, the result is passed as an array of bytes to the caller.

    public bool TryDecrypt(
        Key key,
        Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        out byte[] plaintext)

#### Parameters

key
: The key to use for decryption.

nonce
: The nonce to use for decryption.
    This must be the same nonce as used for encryption.

associatedData
: Optional additional data to be authenticated.
    This must be the same additional data as used for encryption.

ciphertext
: The encrypted data to be decrypted and authenticated.

plaintext
: When this method returns, contains an array of bytes that contains the
    decrypted and authenticated data, or `null` if authentication fails.

#### Return Value

`true` if authentication succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Size` is not equal to [[NonceSize|AeadAlgorithm Class#NonceSize]].

ObjectDisposedException
: `key` has been disposed.


### TryDecrypt(Key, Nonce, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Attempts to decrypt and authenticate the specified data using the specified key.
If successful, the specified span of bytes is filled with the result.

    public bool TryDecrypt(
        Key key,
        Nonce nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext)

#### Parameters

key
: The key to use for decryption.

nonce
: The nonce to use for decryption.
    This must be the same nonce as used for encryption.

associatedData
: Optional additional data to be authenticated.
    This must be the same additional data as used for encryption.

ciphertext
: The encrypted data to be decrypted and authenticated.

plaintext
: The span to fill with the decrypted and authenticated data.
    The length of the span must be equal to `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]]. `plaintext` must not overlap with
    `ciphertext`, except if `plaintext` and `ciphertext` point exactly at the
    same memory location (in-place decryption).

#### Return Value

`true` if authentication succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Size` is not equal to [[NonceSize|AeadAlgorithm Class#NonceSize]].

ArgumentException
: `plaintext.Length` is not equal to `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]].

ArgumentException
: `plaintext` overlaps with `ciphertext`.

ObjectDisposedException
: `key` has been disposed.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods give the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
    * [[Nonce Struct]]
