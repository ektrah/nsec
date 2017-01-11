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

Get the size, in bytes, of a key.

    public int KeySize { get; }

#### Property value

The size, in bytes, of a key.


### MaxNonceSize

Gets the maximum size, in bytes, of a nonce.

    public int MaxNonceSize { get; }

#### Property value

The maximum size, in bytes, of a nonce.


### MinNonceSize

Gets the minimum size, in bytes, of a nonce.

    public int MinNonceSize { get; }

#### Property value

The minimum size, in bytes, of a nonce.


### TagSize

Gets the size, in bytes, of an authentication tag.

    public int TagSize { get; }

#### Property value

The size, in bytes, of an authentication tag.


## Methods


### Decrypt(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Decrypts and authenticates the specified data using the specified key and
returns the result as an array of bytes.

    public byte[] Decrypt(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext)

#### Parameters

key
: The key to use for decryption.

nonce
: The nonce to use for decryption.
    This must be the same nonce used for encryption.

associatedData
: Optional additional data to be authenticated.
    This must be the same additional data used for encryption.

ciphertext
: The encrypted data to be decrypted and authenticated.

#### Return value

An array of bytes that contains the decrypted and authenticated data.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|AeadAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|AeadAlgorithm Class#MaxNonceSize]].

CryptographicException
: Authentication failed.

ObjectDisposedException
: `key` has been disposed.


### Decrypt(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Decrypts and authenticates the specified data using the specified key and fills
the specified span of bytes with the result.

    public void Decrypt(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext)

#### Parameters

key
: The key to use for decryption.

nonce
: The nonce to use for decryption.
    This must be the same nonce used for encryption.

associatedData
: Optional additional data to be authenticated.
    This must be the same additional data used for encryption.

ciphertext
: The encrypted data to be decrypted and authenticated.

plaintext
: The span to fill with the decrypted and authenticated data.
    The length of the span must be `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]].

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|AeadAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|AeadAlgorithm Class#MaxNonceSize]].

ArgumentException
: `plaintext.Length` is not equal to `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]].

CryptographicException
: `ciphertext.length` is less than
    [[TagSize|AeadAlgorithm Class#TagSize]].

CryptographicException
: Authentication failed.

ObjectDisposedException
: `key` has been disposed.


### Encrypt(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Encrypts the specified data using the specified key and returns the result,
which includes an authentication tag, as an array of bytes.

    public byte[] Encrypt(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext)

#### Parameters

key
: The key to use for encryption.

nonce
: The nonce to use for encryption.
    The nonce must not be used more than once with the specified key.

associatedData
: Optional additional data to be authenticated during decryption.

plaintext
: The data to be encrypted.

#### Return value

An array of bytes that contains the encrypted data and the authentication tag.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|AeadAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|AeadAlgorithm Class#MaxNonceSize]].

ArgumentException
: `plaintext.Length` plus [[TagSize|AeadAlgorithm Class#TagSize]]
    is greater than `Int32.MaxValue`.

ObjectDisposedException
: `key` has been disposed.


### Encrypt(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Encrypts the specified data using the specified key and fills the specified
span of bytes with the result, which includes an authentication tag.

    public void Encrypt(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext)

#### Parameters

key
: The key to use for encryption.

nonce
: The nonce to use for encryption.
    The nonce must not be used more than once with the specified key.

associatedData
: Optional additional data to be authenticated during decryption.

plaintext
: The data to be encrypted.

ciphertext
: The span to fill with the encrypted data and the authentication tag.
    The length of the span must be `plaintext.Length` plus
    [[TagSize|AeadAlgorithm Class#TagSize]].

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|AeadAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|AeadAlgorithm Class#MaxNonceSize]].

ArgumentException
: `plaintext.Length` plus [[TagSize|AeadAlgorithm Class#TagSize]]
    is greater than `Int32.MaxValue`.

ArgumentException
: `ciphertext.Length` is not equal to `plaintext.Length` plus
    [[TagSize|AeadAlgorithm Class#TagSize]].

ObjectDisposedException
: `key` has been disposed.


### TryDecrypt(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, out byte[])

Attempts to decrypt and authenticate the specified data using the specified key.
If successful, the result is passed as an array of bytes to the caller.

    public bool TryDecrypt(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        out byte[] plaintext)

#### Parameters

key
: The key to use for decryption.

nonce
: The nonce to use for decryption.
    This must be the same nonce used for encryption.

associatedData
: Optional additional data to be authenticated.
    This must be the same additional data used for encryption.

ciphertext
: The encrypted data to be decrypted and authenticated.

plaintext
: When this method returns, contains an array of bytes that contains the
    decrypted and authenticated data, or `null` if authentication failed.

#### Return value

`true` if authentication succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|AeadAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|AeadAlgorithm Class#MaxNonceSize]].

ObjectDisposedException
: `key` has been disposed.


### TryDecrypt(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Attempts to decrypt and authenticate the specified data using the specified key.
If successful, the specified span of bytes is filled with the result.

    public bool TryDecrypt(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext)

#### Parameters

key
: The key to use for decryption.

nonce
: The nonce to use for decryption.
    This must be the same nonce used for encryption.

associatedData
: Optional additional data to be authenticated.
    This must be the same additional data used for encryption.

ciphertext
: The encrypted data to be decrypted and authenticated.

plaintext
: The span to fill with the decrypted and authenticated data.
    The length of the span must be `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]].

#### Return value

`true` if authentication succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadAlgorithm|AeadAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|AeadAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|AeadAlgorithm Class#MaxNonceSize]].

ArgumentException
: `plaintext.Length` is not equal to `ciphertext.Length` minus
    [[TagSize|AeadAlgorithm Class#TagSize]].

ObjectDisposedException
: `key` has been disposed.


## See also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
