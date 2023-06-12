# IncrementalSignatureVerification Struct

Represents the state of a signature verification algorithm that can be incrementally updated with
segments of data.

    public readonly struct IncrementalSignatureVerification

The type provides an "init, update, final" interface for verifying a signature: First, a
state needs to be initialized with the signature algorithm to be used and the key. The state can
then be updated zero or more times with segments of data. Finalizing the state
yields a result that is identical to the signature verification of the concatenated segments.

[[IncrementalSignatureVerification|IncrementalSignatureVerification Struct]] instances have value-type semantics:
Passing an instance to a method or assigning it to a variable creates a copy of
the state.


## Example

The following C# example shows how to verify a computed signature from multiple segments of
data:

    {{Incremental Verify}}


## [TOC] Summary


## Properties


### Algorithm

Gets the algorithm that was used to initialize the state.

    public SignatureAlgorithm2? Algorithm { get; }

#### Property Value

An instance of the [[SignatureAlgorithm2|SignatureAlgorithm2 Class]] class, or `null` if the
current instance has not been initialized yet or if it has been finalized.


## Static Methods


### Initialize(SignatureAlgorithm2, out IncrementalSignatureVerification)

Initializes the [[IncrementalSignatureVerification|IncrementalSignatureVerification Struct]] state with the
specified signature algorithm.

    public static void Initialize(
        SignatureAlgorithm2 algorithm,
        PublicKey publicKey,
        out IncrementalSignatureVerification state)

#### Parameters

algorithm
: The signature algorithm to use for computing the signature.

publicKey
: The key used to verify the signature of the data.

state
: When this method returns, contains the initialized state.

#### Exceptions

ArgumentNullException
: `algorithm` is `null` or `publicKey` is `null`.

ArgumentException
: `publicKey` algorithm does not match `algorithm`.

### Update(ref IncrementalSignatureVerification, ReadOnlySpan<byte>)

Updates the [[IncrementalSignatureVerification|IncrementalSignatureVerification Struct]] state with the specified
span of bytes.

    public static void Update(
        ref IncrementalSignatureVerification state,
        ReadOnlySpan<byte> data)

#### Parameters

state
: The state to be updated with `data`.

data
: A segment of the data used to verify the signature.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


### Finalize(ref IncrementalSignatureVerification, ReadOnlySpan<byte>)

Completes the signature computation and returns the result as an array of bytes.

    public static bool FinalizeAndVerify(
        ref IncrementalSignatureVerification state,
        ReadOnlySpan<byte> signature)

#### Parameters

state
: The state to be finalized.

signature
: The signature to be validated

#### Return Value

A boolean result if the signature is valid.

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
    * [[SignatureAlgorithm Class]]
    * [[SignatureAlgorithm2 Class]]
    * [[IncrementalSignature Struct]]
