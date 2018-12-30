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


### Blake2b_128

Gets the BLAKE2b algorithm with a 256-bit key and a 128-bit output.

    public static Blake2bMac Blake2b_128 { get; }


### Blake2b_256

Gets the BLAKE2b algorithm with a 256-bit key and a 256-bit output.

    public static Blake2bMac Blake2b_256 { get; }


### Blake2b_512

Gets the BLAKE2b algorithm with a 256-bit key and a 512-bit output.

    public static Blake2bMac Blake2b_512 { get; }


### HmacSha256

Gets the HMAC-SHA256 algorithm with a 256-bit key and a 256-bit output.

    public static HmacSha256 HmacSha256 { get; }


### HmacSha256_128

Gets the HMAC-SHA256 algorithm with a 256-bit key and a truncated, 128-bit output.

    public static HmacSha256 HmacSha256_128 { get; }


### HmacSha512

Gets the HMAC-SHA512 algorithm with a 512-bit key and a 512-bit output.

    public static HmacSha512 HmacSha512 { get; }


### HmacSha512_256

Gets the HMAC-SHA512 algorithm with a 512-bit key and a truncated, 256-bit output.

    public static HmacSha512 HmacSha512_256 { get; }


## Properties


### KeySize

Gets the size of keys.

    public int KeySize { get; }

#### Property Value

The key size, in bytes.


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


### Verify(Key, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Verifies the specified input data using the specified key and message
authentication code.

    public bool Verify(
        Key key,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> mac)

#### Parameters

key
: The key to use for verification.
    Verification fails if this is not the key used when computing the message
    authentication code.

data
: The data to verify.
    Verification fails if the integrity of the data was compromised.

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

## Thread Safety

All members of this type are thread safe.


## Purity

All methods yield the same result for the same arguments.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[IncrementalMac Struct]]
    * [[Key Class]]
