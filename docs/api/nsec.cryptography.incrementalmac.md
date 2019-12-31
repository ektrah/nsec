# IncrementalMac Struct

Represents the state of a message authentication code (MAC) algorithm that can
be incrementally updated with segments of data.

    public readonly struct IncrementalMac

This type provides an "init, update, final" interface for computing a MAC:
First, a state needs to be initialized with a MAC key to be used. The state can
then be updated zero or more times with segments of data. Finalizing the state
yields a result that is identical to the MAC of the concatenated segments.

[[IncrementalMac|IncrementalMac Struct]] instances have value-type semantics:
Passing an instance to a method or assigning it to a variable creates a copy of
the state.


## Example

The following C# example shows how to compute a message authentication code from
multiple segments of data:

    {{Incremental MAC}}


## [TOC] Summary


## Properties


### Algorithm

Gets the algorithm that was used to initialize the state.

    public MacAlgorithm Algorithm { get; }

#### Property Value

An instance of the [[MacAlgorithm|MacAlgorithm Class]] class, or `null` if the
current instance has not been initialized yet or if it has been finalized.


## Static Methods


### Initialize(Key, out IncrementalMac)

Initializes the [[IncrementalMac|IncrementalMac Struct]] state with the
specified key.

    public static void Initialize(
        Key key,
        out IncrementalMac state)

#### Parameters

key
: The key to use for computing the message authentication code.

state
: When this method returns, contains the initialized state.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not an instance of the [[MacAlgorithm|MacAlgorithm Class]]
    class.

ObjectDisposedException
: `key` has been disposed.


### Update(ref IncrementalMac, ReadOnlySpan<byte>)

Updates the [[IncrementalMac|IncrementalMac Struct]] state with the specified
span of bytes.

    public static void Update(
        ref IncrementalMac state,
        ReadOnlySpan<byte> data)

#### Parameters

state
: The state to be updated with `data`.

data
: A segment of the data to be authenticated.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


### Finalize(ref IncrementalMac)

Completes the MAC computation and returns the result as an array of bytes.

    public static byte[] Finalize(
        ref IncrementalMac state)

#### Parameters

state
: The state to be finalized.

#### Return Value

The computed message authentication code.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


### Finalize(ref IncrementalMac, Span<byte>)

Completes the MAC computation and fills the specified span of bytes with the
result.

    public static void Finalize(
        ref IncrementalMac state,
        Span<byte> mac)

#### Parameters

state
: The state to be finalized.

mac
: The span to fill with the computed message authentication code.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.

ArgumentException
: `mac.Length` is not equal to [[MacSize|MacAlgorithm Class#MacSize]].


### FinalizeAndVerify(ref IncrementalMac, ReadOnlySpan<byte>)

Completes the MAC computation and verifies that the result equals the specified
message authentication code.

    public static bool FinalizeAndVerify(
        ref IncrementalMac state,
        ReadOnlySpan<byte> mac)

#### Parameters

state
: The state to be finalized.

mac
: The message authentication code to be verified.

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
    * [[IncrementalHash Struct]]
    * [[Key Class]]
    * [[MacAlgorithm Class]]
