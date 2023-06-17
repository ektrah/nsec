# IncrementalSignatureVerification Struct

Represents the state of a signature verification algorithm that can be incrementally updated with
segments of data.

    public readonly struct IncrementalSignatureVerification

The type provides an "init, update, final" interface for verifying data given a
public key and a signature. First, a state needs to be initialized with the
public key. The state can then be updated zero or more times with segments of
data. Finalizing the state gives a result as to whether verification of the
concatenated segments was successful.

!!! Note
    [[IncrementalSignatureVerification|IncrementalSignatureVerification Struct]]
    instances have value-type semantics: Passing an instance to a method or
    assigning it to a variable creates a copy of the state. It is therefore
    recommended to always pass instances using `ref`, `in`, or `out`.


## Example

The following C# example shows how to verify multiple segments of data given a
public key and a signature:

    {{Incremental Signature Verification}}


## [TOC] Summary


## Properties


### Algorithm

Gets the algorithm that was used to initialize the state.

    public SignatureAlgorithm2? Algorithm { get; }

#### Property Value

An instance of the [[SignatureAlgorithm2|SignatureAlgorithm2 Class]] class, or `null` if the
current instance has not been initialized yet or if it has been finalized.


## Static Methods


### Initialize(PublicKey, out IncrementalSignatureVerification)

Initializes the
[[IncrementalSignatureVerification|IncrementalSignatureVerification Struct]]
state with the specified public key.

    public static void Initialize(
        PublicKey publicKey,
        out IncrementalSignatureVerification state)

#### Parameters

publicKey
: The public key to use for verifying the data.

state
: When this method returns, contains the initialized state.

#### Exceptions

ArgumentNullException
: `publicKey` is `null`.

ArgumentException
: `publicKey.Algorithm` is not an instance of the
    [[SignatureAlgorithm2|SignatureAlgorithm2 Class]] class.


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
: A segment of the data to verify.

#### Exceptions

InvalidOperationException
: `state` has not been initialized yet or has already been finalized.


### FinalizeAndVerify(ref IncrementalSignatureVerification, ReadOnlySpan<byte>)

Completes the verification.

    public static bool FinalizeAndVerify(
        ref IncrementalSignatureVerification state,
        ReadOnlySpan<byte> signature)

#### Parameters

state
: The state to be finalized.

signature
: The signature of the data to verify.

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
    * [[IncrementalSignature Struct]]
    * [[PublicKey Class]]
    * [[SignatureAlgorithm2 Class]]
