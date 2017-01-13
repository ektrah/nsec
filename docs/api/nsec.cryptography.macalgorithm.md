# MacAlgorithm Class

Represents a message authentication code (MAC) algorithm.

    public abstract class MacAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **MacAlgorithm**
        * HmacSha256
        * HmacSha512


## [TOC] Summary


## Properties


### DefaultKeySize

Gets the default key size, in bytes.

    public int DefaultKeySize { get; }

#### Property value

The default key size, in bytes.


### DefaultMacSize

Gets the default MAC size, in bytes.

    public int DefaultMacSize { get; }

#### Property value

The default MAC size, in bytes.


### MaxKeySize

Gets the maximum key size, in bytes.

    public int MaxKeySize { get; }

#### Property value

The maximum key size, in bytes.


### MaxNonceSize

Gets the maximum nonce size, in bytes.

    public int MaxNonceSize { get; }

#### Property value

The maximum nonce size, in bytes.


### MaxMacSize

Gets the maximum MAC size, in bytes.

    public int MaxMacSize { get; }

#### Property value

The maximum MAC size, in bytes.


### MinKeySize

Gets the minimum key size, in bytes.

    public int MinKeySize { get; }

#### Property value

The minimum key size, in bytes.


### MinNonceSize

Gets the minimum nonce size, in bytes.

    public int MinNonceSize { get; }

#### Property value

The minimum nonce size, in bytes.


### MinMacSize

Gets the minimum MAC size, in bytes.

    public int MinMacSize { get; }

#### Property value

The minimum MAC size, in bytes.


## Methods


### Sign(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Computes a message authentication code for the specified input data using the
specified key and returns it as an array of bytes.

    public byte[] Sign(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> data)

#### Parameters

key
: The key to use for signing.

nonce
: The nonce to use for signing.
    The nonce must not be used more than once with the specified key,
    unless both [[MinNonceSize|MacAlgorithm Class#MinNonceSize]] and
    `nonce.Length` are 0.

data
: The data to be signed.

#### Return value

The computed message authentication code.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|MacAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|MacAlgorithm Class#MaxNonceSize]].

ObjectDisposedException
: `key` has been disposed.


### Sign(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, int)

Computes a message authentication code for the specified input data using the
specified key and returns it as an array of bytes of the specified size.

    public byte[] Sign(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> data,
        int macSize)

#### Parameters

key
: The key to use for signing.

nonce
: The nonce to use for signing.
    The nonce must not be used more than once with the specified key,
    unless both [[MinNonceSize|MacAlgorithm Class#MinNonceSize]] and
    `nonce.Length` are 0.

data
: The data to be signed.

macSize
: The size, in bytes, of the message authentication code to compute.

#### Return value

The computed message authentication code.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|MacAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|MacAlgorithm Class#MaxNonceSize]].

ArgumentOutOfRangeException
: `macSize` is less than
    [[MinMacSize|MacAlgorithm Class#MinMacSize]] or greater than
    [[MaxMacSize|MacAlgorithm Class#MaxMacSize]].

ObjectDisposedException
: `key` has been disposed.


### Sign(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with a message authentication code for the
specified input data using the specified key.

    public void Sign(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> data,
        Span<byte> mac)

#### Parameters

key
: The key to use for signing.

nonce
: The nonce to use for signing.
    The nonce must not be used more than once with the specified key,
    unless both [[MinNonceSize|MacAlgorithm Class#MinNonceSize]] and
    `nonce.Length` are 0.

data
: The data to be signed.

mac
: The span to fill with the computed message authentication code.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|MacAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|MacAlgorithm Class#MaxNonceSize]].

ArgumentException
: `mac.Length` is less than
    [[MinMacSize|MacAlgorithm Class#MinMacSize]] or greater than
    [[MaxMacSize|MacAlgorithm Class#MaxMacSize]].

ObjectDisposedException
: `key` has been disposed.


### TryVerify(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Attempts to verify the message authentication for the specified input data using
the specified key.

    public bool TryVerify(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> mac)

#### Parameters

key
: The key to use for verification.

nonce
: The nonce to use for verification.
    This must be the same nonce used for signing.

data
: The data to be verified.

mac
: The message authentication code to be verified.

#### Return value

`true` if verification succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|MacAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|MacAlgorithm Class#MaxNonceSize]].

ObjectDisposedException
: `key` has been disposed.


### Verify(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Verifies the message authentication code for the specified input data using the
specified key.

    public void Verify(
        Key key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> mac)

#### Parameters

key
: The key to use for verification.

nonce
: The nonce to use for verification.
    This must be the same nonce used for signing.

data
: The data to be verified.

mac
: The message authentication code to be verified.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

ArgumentException
: `nonce.Length` is less than
    [[MinNonceSize|MacAlgorithm Class#MinNonceSize]] or greater than
    [[MaxNonceSize|MacAlgorithm Class#MaxNonceSize]].

ArgumentException
: `mac.Length` is less than
    [[MinMacSize|MacAlgorithm Class#MinMacSize]] or greater than
    [[MaxMacSize|MacAlgorithm Class#MaxMacSize]].

ObjectDisposedException
: `key` has been disposed.


## See also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
