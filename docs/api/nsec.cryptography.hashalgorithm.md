# HashAlgorithm Class

Represents a cryptographic hash algorithm.

    public abstract class HashAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **HashAlgorithm**
        * Blake2b
        * Sha256
        * Sha512


## [TOC] Summary


## Properties


### DefaultHashSize

Gets the default hash size, in bytes.

    public int DefaultHashSize { get; }

#### Property value

The default hash size, in bytes.



### MaxHashSize

Gets the maximum hash size, in bytes.

    public int MaxHashSize { get; }

#### Property value

The maximum hash size, in bytes.


### MinHashSize

Gets the minimum hash size, in bytes.

    public int MinHashSize { get; }

#### Property value

The minimum hash size, in bytes.


## Methods


### Hash(ReadOnlySpan<byte>)

Computes a hash for the specified input data and returns it as an array of
bytes.

    public byte[] Hash(
        ReadOnlySpan<byte> data)

#### Parameters

data
: The input data to compute the hash for.

#### Return value

The computed hash.

### Hash(ReadOnlySpan<byte>, int)

Computes a hash for the specified input data and returns it as an array of
bytes of the specified size.

    public byte[] Hash(
        ReadOnlySpan<byte> data,
        int hashSize)

#### Parameters

data
: The input data to compute the hash for.

hashSize
: The size, in bytes, of the hash to compute.

#### Return value

The computed hash.

#### Exceptions

ArgumentOutOfRangeException
: `hashSize` is less than [[MinHashSize|HashAlgorithm Class#MinHashSize]] or
    greater than [[MaxHashSize|HashAlgorithm Class#MaxHashSize]].


### Hash(ReadOnlySpan<byte>, Span<byte>)

Fills the specified span of bytes with a hash for the specified input data.

    public void Hash(
        ReadOnlySpan<byte> data,
        Span<byte> hash)

#### Parameters

data
: The input data to compute the hash for.

hash
: The span to fill with the computed hash.

#### Exceptions

ArgumentException
: `hash.Length` is less than
    [[MinHashSize|HashAlgorithm Class#MinHashSize]] or greater than
    [[MaxHashSize|HashAlgorithm Class#MaxHashSize]].


## See also

* API Reference
    * [[Algorithm Class]]
