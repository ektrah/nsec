# RandomNumberGenerator Class

Provides methods for generating random data.

    public abstract class RandomNumberGenerator


## [TOC] Summary


## Static Properties


### Default

Gets the default [[RandomNumberGenerator|RandomNumberGenerator Class]] instance.

    public static RandomNumberGenerator Default { get; }

#### Property Value

An instance of the [[RandomNumberGenerator|RandomNumberGenerator Class]] class
that provides the default random number generator.


## Methods


### GenerateBytes(int)

Generates a cryptographically strong random sequence of values and returns it as
an array of bytes.

    public byte[] GenerateBytes(
        int count)

#### Parameters

count
: The number of bytes to generate.

#### Return Value

An array of bytes that contains the generated values.

#### Exceptions

ArgumentOutOfRangeException
: `count` is less than 0.


### GenerateBytes(Span<byte>)

Fills the specified span of bytes with a cryptographically strong random
sequence of values.

    public void GenerateBytes(
        Span<byte> bytes)

#### Parameters

bytes
: The span to fill with random values.


### GenerateKey(Algorithm, KeyFlags)

Generates a new cryptographic key for the specified algorithm.

    public Key GenerateKey(
        Algorithm algorithm,
        KeyFlags flags = KeyFlags.None)

#### Parameters

algorithm
: The algorithm for the key.

flags
: A bitwise combination of [[KeyFlags|KeyFlags Enum]] values that specifies
    the flags for the new key.

#### Return Value

A new instance of the [[Key|Key Class]] class that represents the new key.

#### Exceptions

ArgumentNullException
: `algorithm` is `null`.

NotSupportedException
: The specified algorithm does not use keys.


## Thread Safety

All members of this type are thread safe.
