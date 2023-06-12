# IncrementalSignature Struct

Represents the state of a signature algorithm that can be incrementally updated with
segments of data.

    public readonly struct IncrementalSignature

The type provides an "init, update, final" interface for generating the signature: First, a
state needs to be initialized with the signature algorithm to be used and the key. The state can
then be updated zero or more times with segments of data. Finalizing the state
yields a result that is identical to the signature of the concatenated segments.

[[IncrementalSignature|IncrementalSignature Struct]] instances have value-type semantics:
Passing an instance to a method or assigning it to a variable creates a copy of
the state.


## Example

The following C# example shows how to compute a signature from multiple segments of
data:

    {{Incremental Signature}}


## [TOC] Summary


## Properties


### Algorithm

Gets the algorithm that was used to initialize the state.

    public SignatureAlgorithm2? Algorithm { get; }

#### Property Value

An instance of the [[SignatureAlgorithm2|SignatureAlgorithm2 Class]] class, or `null` if the
current instance has not been initialized yet or if it has been finalized.


## Static Methods


### Initialize(SignatureAlgorithm2, out IncrementalSignature)

Initializes the [[IncrementalSignature|IncrementalSignature Struct]] state with the
specified signature algorithm.

    public static void Initialize(
        SignatureAlgorithm2 algorithm,
        Key privateKey,
        out IncrementalSignature state)

#### Parameters

algorithm
: The signature algorithm to use for computing the signature.

privateKey
: The key used to sign the data.

state
: When this method returns, contains the initialized state.

#### Exceptions

ArgumentNullException
: `algorithm` is `null` or `privateKey` is `null`.

ArgumentException
: `privateKey` algorithm does not match `algorithm`.

### Update(ref IncrementalSignature, ReadOnlySpan<byte>)

Updates the [[IncrementalSignature|IncrementalSignature Struct]] state with the specified
span of bytes.

    public static void Update(
        ref IncrementalSignature state,
        ReadOnlySpan<byte> data)

#### Parameters

state
: The state to be updated with `data`.

data
: A segment of the data to sign.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


### Finalize(ref IncrementalSignature)

Completes the signature computation and returns the result as an array of bytes.

    public static byte[] Finalize(
        ref IncrementalSignature state)

#### Parameters

state
: The state to be finalized.

#### Return Value

The computed signature.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


### Finalize(ref IncrementalSignature, Span<byte>)

Completes the signature computation and fills the specified span of bytes with the
result.

    public static void Finalize(
        ref IncrementalSignature state,
        Span<byte> signature)

#### Parameters

state
: The state to be finalized.

signature
: The span to fill with the computed signature.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.

ArgumentException
: `signature.Length` is not equal to [[SignatureSize|SignatureAlgorithm Class#SignatureSize]].


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe. As with any other type, reading and writing to
a shared variable that contains an instance of this type must be protected by a
lock to guarantee thread safety.


## See Also

* API Reference
    * [[SignatureAlgorithm Class]]
    * [[SignatureAlgorithm2 Class]]
    * [[IncrementalSignatureVerification Struct]]
