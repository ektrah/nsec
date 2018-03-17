# MacAlgorithm Class

Represents a message authentication code (MAC) algorithm.

    public abstract class MacAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **MacAlgorithm**
        * Blake2bMac
        * HmacSha256
        * HmacSha512


## [TOC] Summary


## Static Properties


### Blake2b_256

Gets the keyed BLAKE2b-256 algorithm.

    public static Blake2bMac Blake2b_256 { get; }


### Blake2b_512

Gets the keyed BLAKE2b-512 algorithm.

    public static Blake2bMac Blake2b_512 { get; }


### HmacSha256

Gets the HMAC-SHA256 algorithm.

    public static HmacSha256 HmacSha256 { get; }


### HmacSha512

Gets the HMAC-SHA512 algorithm.

    public static HmacSha512 HmacSha512 { get; }


## Properties


### DefaultKeySize / MinKeySize / MaxKeySize

Gets the default/minimum/maximum size of keys.

    public int DefaultKeySize { get; }
    public int MinKeySize { get; }
    public int MaxKeySize { get; }

#### Property Value

The default/minimum/maximum key size, in bytes.


### MacSize

Gets the size of a MAC.

    public int MacSize { get; }

#### Property Value

The MAC size, in bytes.


## Methods


### Mac(Key, ReadOnlySpan<byte>)

Computes a message authentication code for the specified input data using the
specified key and returns it as an array of bytes.

    public byte[] Mac(
        Key key,
        ReadOnlySpan<byte> data)

#### Parameters

key
: The key to use for computing the message authentication code.

data
: The data to authenticate.

#### Return Value

The computed message authentication code.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

ObjectDisposedException
: `key` has been disposed.


### Mac(Key, ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with a message authentication code for the
specified input data using the specified key.

    public void Mac(
        Key key,
        ReadOnlySpan<byte> data,
        Span<byte> mac)

#### Parameters

key
: The key to use for computing the message authentication code.

data
: The data to authenticate.

mac
: The span to fill with the computed message authentication code.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

ArgumentException
: `mac.Length` is not equal to [[MacSize|MacAlgorithm Class#MacSize]].

ObjectDisposedException
: `key` has been disposed.


### TryVerify(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Attempts to verify the specified input data using the specified key and message
authentication code.

    public bool TryVerify(
        Key key,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> mac)

#### Parameters

key
: The key to use for verification.
    Verification fails if this is not the same key as used for computing the
    message authentication code.

data
: The data to verify.
    Verification fails if this is not the same data as used for computing the
    message authentication code.

mac
: The message authentication code for the data.

#### Return Value

`true` if verification succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

ObjectDisposedException
: `key` has been disposed.


### Verify(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Verifies the specified input data using the specified key and message
authentication code.

    public void Verify(
        Key key,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> mac)

#### Parameters

key
: The key to use for verification.
    Verification fails if this is not the same key as used for computing the
    message authentication code.

data
: The data to verify.
    Verification fails if this is not the same data as used for computing the
    message authentication code.

mac
: The message authentication code for the data.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[MacAlgorithm|MacAlgorithm Class]] object.

CryptographicException
: Verification failed.

ObjectDisposedException
: `key` has been disposed.


## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[IncrementalMac Struct]]
    * [[Key Class]]
