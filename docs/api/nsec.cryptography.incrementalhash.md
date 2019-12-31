# IncrementalHash Struct

Represents the state of a hash algorithm that can be incrementally updated with
segments of data.

    public readonly struct IncrementalHash

The type provides an "init, update, final" interface for hashing data: First, a
state needs to be initialized with the hash algorithm to be used. The state can
then be updated zero or more times with segments of data. Finalizing the state
yields a result that is identical to the hash of the concatenated segments.

[[IncrementalHash|IncrementalHash Struct]] instances have value-type semantics:
Passing an instance to a method or assigning it to a variable creates a copy of
the state.


## Example

The following C# example shows how to compute a hash from multiple segments of
data:

    {{Incremental Hash}}


## [TOC] Summary


## Properties


### Algorithm

Gets the algorithm that was used to initialize the state.

    public HashAlgorithm Algorithm { get; }

#### Property Value

An instance of the [[HashAlgorithm|HashAlgorithm Class]] class, or `null` if the
current instance has not been initialized yet or if it has been finalized.


## Static Methods


### Initialize(HashAlgorithm, out IncrementalHash)

Initializes the [[IncrementalHash|IncrementalHash Struct]] state with the
specified hash algorithm.

    public static void Initialize(
        HashAlgorithm algorithm,
        out IncrementalHash state)

#### Parameters

algorithm
: The hash algorithm to use for computing the hash.

state
: When this method returns, contains the initialized state.

#### Exceptions

ArgumentNullException
: `algorithm` is `null`.


### Update(ref IncrementalHash, ReadOnlySpan<byte>)

Updates the [[IncrementalHash|IncrementalHash Struct]] state with the specified
span of bytes.

    public static void Update(
        ref IncrementalHash state,
        ReadOnlySpan<byte> data)

#### Parameters

state
: The state to be updated with `data`.

data
: A segment of the data to hash.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


### Finalize(ref IncrementalHash)

Completes the hash computation and returns the result as an array of bytes.

    public static byte[] Finalize(
        ref IncrementalHash state)

#### Parameters

state
: The state to be finalized.

#### Return Value

The computed hash.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


### Finalize(ref IncrementalHash, Span<byte>)

Completes the hash computation and fills the specified span of bytes with the
result.

    public static void Finalize(
        ref IncrementalHash state,
        Span<byte> hash)

#### Parameters

state
: The state to be finalized.

hash
: The span to fill with the computed hash.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.

ArgumentException
: `hash.Length` is not equal to [[HashSize|HashAlgorithm Class#HashSize]].


### FinalizeAndVerify(ref IncrementalHash, ReadOnlySpan<byte>)

Completes the hash computation and verifies that the result equals the specified
hash.

    public static bool FinalizeAndVerify(
        ref IncrementalHash state,
        ReadOnlySpan<byte> hash)

#### Parameters

state
: The state to be finalized.

hash
: The hash to be verified.

#### Return Value

`true` if verification succeeds; otherwise, `false`.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe. As with any other type, reading and writing to
a shared variable that contains an instance of this type must be protected by a
lock to guarantee thread safety.


## See Also

* API Reference
    * [[HashAlgorithm Class]]
    * [[IncrementalMac Struct]]
