# Nonce Struct

Represents a nonce for [[authenticated encryption|AeadAlgorithm Class]].

    public readonly struct Nonce : IEquatable<Nonce>

A [[Nonce|Nonce Struct]] value consists of two fields: a fixed field and a
counter field. The fixed field remains constant for all nonces that are
generated for a given key. The counter fields of successive nonces form a
monotonically increasing sequence, when those fields are regarded as unsigned
integers in big-endian byte order.

In case nonces need to be generated in a different way, the fixed field can be
set to a new value for each encryption operation, and the size of the counter
field to zero.

See [[How to: Generate Nonces]] for additional information on generating nonces.


## [TOC] Summary


## Static Fields


### MaxSize

Represents the largest possible size of a nonce, in bytes.

    public static readonly int MaxSize = 24;

This field is constant and read-only.


## Constructors


### Nonce()

Initializes a new instance of [[Nonce|Nonce Struct]] with a zero-length fixed
field and a zero-length counter field.

    public Nonce()


### Nonce(int, int)

Initializes a new instance of [[Nonce|Nonce Struct]] with a fixed field and a
counter field of the specified sizes. Both fields are initialized to zeros.

    public Nonce(
        int fixedFieldSize,
        int counterFieldSize)

#### Parameters

fixedFieldSize
: The size of the fixed field.

counterFieldSize
: The size of the counter field.

#### Exceptions

ArgumentOutOfRangeException
: `fixedFieldSize` or `counterFieldSize` is less than 0.

ArgumentOutOfRangeException
: `fixedFieldSize + counterFieldSize` is greater than
    [[MaxSize|Nonce Struct#MaxSize]].


### Nonce(ReadOnlySpan<byte>, int)

Initializes a new instance of [[Nonce|Nonce Struct]] with the specified fixed
field and a counter field of the specified size. The counter field is
initialized to zero.

    public Nonce(
        ReadOnlySpan<byte> fixedField,
        int counterFieldSize)

#### Parameters

fixedField
: The fixed field.

counterFieldSize
: The size of the counter field.

#### Exceptions

ArgumentException
: `fixedField.Length` is greater than [[MaxSize|Nonce Struct#MaxSize]].

ArgumentOutOfRangeException
: `counterFieldSize` is less than 0.

ArgumentOutOfRangeException
: `fixedField.Length + counterFieldSize` is greater than
    [[MaxSize|Nonce Struct#MaxSize]].


### Nonce(ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Initializes a new instance of [[Nonce|Nonce Struct]] with the specified fixed
field and and the specified counter field.

    public Nonce(
        ReadOnlySpan<byte> fixedField,
        ReadOnlySpan<byte> counterField)

#### Parameters

fixedField
: The fixed field.

counterField
: The counter field.

#### Exceptions

ArgumentException
: `fixedField.Length + counterField.Length` is greater than
    [[MaxSize|Nonce Struct#MaxSize]].


## Properties


### CounterFieldSize

Gets the size of the counter field.

    public int CounterFieldSize { get; }

#### Property Value

The size of the counter field, in bytes.


### FixedFieldSize

Gets the size of the fixed field.

    public int FixedFieldSize { get; }

#### Property Value

The size of the fixed field, in bytes.


### Size

Gets the total size of the nonce.

    public int Size { get; }

#### Property Value

The total size of the nonce, in bytes.


## Static Methods


### Equals(in Nonce, in Nonce)

Returns a value indicating whether two specified instances of [[Nonce|Nonce
Struct]] represent the same value.

    public static bool Equals(
        in Nonce left,
        in Nonce right)

#### Parameters

left
: The first value to compare.

right
: The second value to compare.

#### Return Value

`true` if `left` and `right` are equal; otherwise, `false`.

#### Remarks

This method is equivalent to `left.Equals(right)` but faster.


### TryAdd(ref Nonce, int)

Attempts to add the specified value to the counter field of the specified
[[Nonce|Nonce Struct]].

    public static bool TryAdd(
        ref Nonce nonce,
        int value)

#### Parameters

nonce
: The nonce with the counter field to add the value to.

value
: The value to add to the counter field of the nonce. The value must be greater
    than or equal to 0.

#### Return Value

`false` if the addition of the value overflows the counter field of the nonce;
otherwise, `true`.

#### Exceptions

ArgumentOutOfRangeException
: `value` is negative.

#### Remarks

This method is equivalent to `nonce += value;` but faster.


### TryIncrement(ref Nonce)

Attempts to increment the counter field of the specified [[Nonce|Nonce Struct]]
by 1.

    public static bool TryIncrement(
        ref Nonce nonce)

#### Parameters

nonce
: The nonce with the counter field to increment.

#### Return Value

`false` if the increment overflows the counter field of the nonce; otherwise,
`true`.

#### Remarks

This method is equivalent to `nonce++;` but faster.


### Xor(ref Nonce, in Nonce)

Performs a bitwise exclusive Or (XOr) operation on the specified [[Nonce|Nonce
Struct]] values and stores the result in the first parameter.

    public static void Xor(
        ref Nonce nonce,
        in Nonce other)

#### Parameters

nonce
: A nonce to perform the XOr operation on.

other
: A nonce to perform the XOr operation on.

#### Exceptions

ArgumentException
: The sizes of the two nonces are not the same.

#### Remarks

This method is equivalent to `nonce ^= other;` but faster.


## Methods


### CopyTo(Span<byte>)

Copies the current [[Nonce|Nonce Struct]] to the specified span of bytes.

    public void CopyTo(
        Span<byte> destination)

#### Parameters

destination
: The span of bytes that is the destination of the elements copied from the
    current nonce.

#### Exceptions

ArgumentException
: The size of the current nonce is greater than the available number of bytes
    in `destination`.


### Equals(Nonce)

Returns a value indicating whether the current [[Nonce|Nonce Struct]] and the
specified [[Nonce|Nonce Struct]] represent the same value.

    public bool Equals(
        Nonce other)

#### Parameters

other
: A nonce to compare to the current nonce.

#### Return Value

`true` if `other` is equal to the current nonce; otherwise, `false`.


### ToArray()

Copies the current [[Nonce|Nonce Struct]] to a new array of bytes.

    public byte[] ToArray()

#### Return Value

A new array of bytes containing a copy of the current nonce.


## Operators


### Addition(Nonce, int)

Returns a new [[Nonce|Nonce Struct]] by adding the specified value to the
counter field of the specified [[Nonce|Nonce Struct]].

    public static Nonce operator +(
        Nonce nonce,
        int value)

#### Parameters

nonce
: The nonce with the counter field to add the value to.

value
: The value to add to the counter field of the nonce. The value must be greater
    than or equal to 0.

#### Return Value

The `nonce` with `value` added to the counter field.

#### Exceptions

OverflowException
: The addition of the value overflows the counter field of the nonce.


### Equality(Nonce, Nonce)

Returns a value that indicates whether two [[Nonce|Nonce Struct]] values are
equal.

    public static bool operator ==(
        Nonce left,
        Nonce right)

#### Parameters

left
: The first value to compare.

right
: The second value to compare.

#### Return Value

`true` if `left` and `right` are equal; otherwise, `false`.


### Increment(Nonce)

Returns a new [[Nonce|Nonce Struct]] by incrementing the counter field of the
specified [[Nonce|Nonce Struct]] by 1.

    public static Nonce operator ++(
        Nonce nonce)

#### Parameters

nonce
: The nonce with the counter field to increment.

#### Return Value

The nonce with the counter field incremented by 1.

#### Exceptions

OverflowException
: The increment overflows the counter field of the nonce.


### Inequality(Nonce, Nonce)

Returns a value that indicates whether two [[Nonce|Nonce Struct]] values are
not equal.

    public static bool operator !=(
        Nonce left,
        Nonce right)

#### Parameters

left
: The first value to compare.

right
: The second value to compare.

#### Return Value

`true` if `left` and `right` are not equal; otherwise, `false`.


### Xor(Nonce, Nonce)

Returns a new [[Nonce|Nonce Struct]] by performing a bitwise exclusive Or (XOr)
operation on the specified [[Nonce|Nonce Struct]] values.

    public static Nonce operator ^(
        Nonce left,
        Nonce right)

#### Parameters

left
: A nonce to perform the XOr operation on.

right
: A nonce to perform the XOr operation on.

#### Return Value

The result of the XOr operation.

#### Exceptions

ArgumentException
: The sizes of the two nonces are not the same.


## Thread Safety

All members of this type are thread safe. Members that appear to modify instance
state actually return a new instance initialized with the new value. As with any
other type, reading and writing to a shared variable that contains an instance
of this type must be protected by a lock to guarantee thread safety.


## See Also

* API Reference
    * [[AeadAlgorithm Class]]
* Working with NSec
    * [[How to: Generate Nonces]]
