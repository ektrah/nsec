# AeadDetachedAlgorithm Class

Represents an authenticated encryption with associated data (AEAD) algorithm.

    public abstract class AeadDetachedAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **AeadDetachedAlgorithm**
        * Aes256Gcm


## [TOC] Summary


## Static Properties


### Aes256Gcm

Gets the AES256-GCM AEAD algorithm.

    public static Aes256GcmDetached Aes256Gcm { get; }

#### Exceptions

PlatformNotSupportedException
: The platform does not support hardware-accelerated AES.

#### Remarks

The AES-GCM implementation in NSec is hardware-accelerated and may not be
available on all architectures. Support can be determined at runtime using
the static `IsSupported` property of the `NSec.Cryptography.AesDetached256Gcm` class.


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


### Encrypt(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>, Span<byte>)

Encrypts the specified plaintext using the specified key, nonce, and associated
data, and fills the specified span of bytes with the ciphertext, which includes
an authentication tag.

    public void Encrypt(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag)

#### Parameters

key
: The [[Key|Key Class]] to use for encryption.
    This must be a cryptographically strong key as created by the
    [[Key.Create|Key Class#Create]] class, not a password.

nonce
: The nonce to use for encryption.
    The same nonce must not be used more than once to encrypt data with the
    specified key.

!!! Note
    Using the same nonce with the same key more than once leads to
    catastrophic loss of security.

: To prevent nonce reuse when encrypting multiple plaintexts with the same key,
    it is recommended to increment the previous nonce. A randomly generated
    nonce is unsafe unless the [[nonce size|AeadDetachedAlgorithm Class#NonceSize]]
    is at least 24 bytes.

associatedData
: Optional additional data to be authenticated during decryption.

plaintext
: The data to encrypt.

ciphertext
: The span to fill with the encrypted data.
    The length of the span must be equal to `plaintext.Length`.
: `ciphertext` must not overlap in memory with `plaintext`, except if
    `ciphertext` and `plaintext` point at exactly the same memory location
    (in-place encryption).

tag
: The span to fill with the authentication tag.
    The length of the span must be equal to [[TagSize|AeadDetachedAlgorithm Class#TagSize]].

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[AeadDetachedAlgorithm|AeadDetachedAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is not equal to [[NonceSize|AeadDetachedAlgorithm Class#NonceSize]].

ArgumentException
: `ciphertext.Length` is not equal to `plaintext.Length`.

ArgumentException
: `ciphertext` overlaps in memory with `plaintext`.

ArgumentException
: `tag.Length` is not equal to [[TagSize|AeadDetachedAlgorithm Class#TagSize]].

ObjectDisposedException
: `key` has been disposed.


### Decrypt(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Decrypts and authenticates the specified ciphertext using the specified key,
nonce, and associated data. If successful, fills the specified span of bytes
with the decrypted plaintext.

    public bool Decrypt(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)

#### Parameters

key
: The [[Key|Key Class]] to use for decryption.
    Authentication fails if this is not the same key that was used for
    encryption.

nonce
: The nonce to use for decryption.
    Authentication fails if this is not the same nonce that was used for
    encryption.

associatedData
: Optional additional data to authenticate.
    Authentication fails if this is not the same additional data that was used
    for encryption.

ciphertext
: The encrypted data to authenticate and decrypt.
    Authentication fails if the integrity of the data was compromised.

tag
: The data used to authenticate the encrypted data and additional data
    Authentication fails if the encryptes data was compromised or additional data is not the same that was used for encryption.

plaintext
: The span to fill with the decrypted and authenticated data.
    The length of the span must be equal to `ciphertext.Length`.
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
    [[AeadDetachedAlgorithm|AeadDetachedAlgorithm Class]] object.

ArgumentException
: `tag.Length` is not equal to [[TagSize|AeadDetachedAlgorithm Class#TagSize]].

ArgumentException
: `plaintext.Length` is not equal to `ciphertext.Length`.

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
