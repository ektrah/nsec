# IncrementalHash Struct

TODO

    public struct IncrementalHash


## Example

    {{Incremental Hash}}


## [TOC] Summary


## Static Methods


### Initialize(HashAlgorithm, out IncrementalHash)

    public static void Initialize(
        HashAlgorithm algorithm,
        out IncrementalHash state)


### Update(ref IncrementalHash, ReadOnlySpan<byte>)

    public static void Update(
        ref IncrementalHash state,
        ReadOnlySpan<byte> data)


### Finalize(ref IncrementalHash)

    public static byte[] Finalize(
        ref IncrementalHash state)


### Finalize(ref IncrementalHash, Span<byte>)

    public static void Finalize(
        ref IncrementalHash state,
        Span<byte> hash)


### FinalizeAndTryVerify(ref IncrementalHash, ReadOnlySpan<byte>)

    public static bool FinalizeAndTryVerify(
        ref IncrementalHash state,
        ReadOnlySpan<byte> hash)


### FinalizeAndVerify(ref IncrementalHash, ReadOnlySpan<byte>)

    public static void FinalizeAndVerify(
        ref IncrementalHash state,
        ReadOnlySpan<byte> hash)


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe. As with any other type, reading and writing to
a shared variable that contains an instance of this type must be protected by a
lock to guarantee thread safety.


## See Also

* API Reference
    * [[HashAlgorithm Class]]
