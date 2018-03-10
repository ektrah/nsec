# IncrementalMac Struct

TODO

    public struct IncrementalMac


## Example

    {{Incremental MAC}}


## [TOC] Summary


## Static Methods


### Initialize(Key, out IncrementalMac)

    public static void Initialize(
        Key key,
        out IncrementalMac state)


### Update(ref IncrementalMac, ReadOnlySpan<byte>)

    public static void Update(
        ref IncrementalMac state,
        ReadOnlySpan<byte> data)


### Finalize(ref IncrementalMac)

    public static byte[] Finalize(
        ref IncrementalMac state)


### Finalize(ref IncrementalMac, Span<byte>)

    public static void Finalize(
        ref IncrementalMac state,
        Span<byte> mac)


### FinalizeAndTryVerify(ref IncrementalMac, ReadOnlySpan<byte>)

    public static bool FinalizeAndTryVerify(
        ref IncrementalMac state,
        ReadOnlySpan<byte> mac)


### FinalizeAndVerify(ref IncrementalMac, ReadOnlySpan<byte>)

    public static void FinalizeAndVerify(
        ref IncrementalMac state,
        ReadOnlySpan<byte> mac)


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe. As with any other type, reading and writing to
a shared variable that contains an instance of this type must be protected by a
lock to guarantee thread safety.


## See Also

* API Reference
    * [[MacAlgorithm Class]]
    * [[Key Class]]
