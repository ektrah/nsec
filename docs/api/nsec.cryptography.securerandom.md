# SecureRandom Class

Provides static methods for generating random data.

    public static class SecureRandom


## [TOC] Summary


## Methods


### GenerateBytes(int)

Generates a cryptographically strong random sequence of values and returns it as
an array of bytes.

    public static byte[] GenerateBytes(
        int count)

#### Parameters

count
: The number of bytes to generate.

#### Exceptions

ArgumentOutOfRangeException
: `count` is less than 0.


### GenerateBytes(Span<byte>)

Fills the specified span of bytes with a cryptographically strong random
sequence of values.

    public static void GenerateBytes(
        Span<byte> bytes)

#### Parameters

bytes
: The span to fill with random values.


## Thread Safety

All members of this type are thread safe.
