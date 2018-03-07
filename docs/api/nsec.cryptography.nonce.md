# Nonce Struct

Represents a nonce for [[authenticated encryption|AeadAlgorithm Class]].

    public readonly struct Nonce : IEquatable<Nonce>

A nonce consists of two fields: a fixed field and a counter field. The counter
fields of successive nonces form a monotonically increasing sequence, when those
fields are regarded as unsigned integers in big-endian byte order. The length of
both the fixed field and the counter field must remain constant for all nonces
that are generated for a given key.


## [TOC] Summary


## Constants


### MaxSize

Represents the largest possible size of a nonce, in bytes.

    public const int MaxSize = 32;

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
: `fixedFieldSize` is greater than [[MaxSize|Nonce Struct#MaxSize]].

ArgumentOutOfRangeException
: `counterFieldSize` is less than 0 or greater than [[MaxSize|Nonce
    Struct#MaxSize]] minus `fixedFieldSize`.


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
: `counterFieldSize` is less than 0 or greater than [[MaxSize|Nonce
    Struct#MaxSize]] minus `fixedField.Length`.


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
: `fixedField.Length` is greater than [[MaxSize|Nonce Struct#MaxSize]].

ArgumentOutOfRangeException
: `counterField.Length` is greater than [[MaxSize|Nonce Struct#MaxSize]] minus
    `fixedField.Length`.


## Properties


### CounterFieldSize

Gets the size of the counter field, in bytes.

    public int CounterFieldSize { get; }

#### Property Value

The size of the counter field, in bytes.


### FixedFieldSize

Gets the size of the fixed field, in bytes.

    public int FixedFieldSize { get; }

#### Property Value

The size of the fixed field, in bytes.


### Size

Gets the total size of the nonce, in bytes.

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


### Xor(ref Nonce, ReadOnlySpan<byte>)

Performs a bitwise exclusive Or (XOr) operation on the specified [[Nonce|Nonce
Struct]] and the specified span of bytes.

    public static void Xor(
        ref Nonce nonce,
        ReadOnlySpan<byte> bytes)

#### Parameters

nonce
: The nonce to perform the XOr operation on.

bytes
: The span of bytes to XOr with the nonce.

#### Exceptions

ArgumentException
: The length of the span of bytes is not equal to the size of the nonce.


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


### Equals(object)

Returns a value indicating whether the current [[Nonce|Nonce Struct]] and the
specified object represent the same type and value.

    public override bool Equals(
        object obj)

#### Parameters

obj
: The object to compare with this instance.

#### Return Value

`true` if `obj` is a [[Nonce|Nonce Struct]] and equal to the current nonce;
otherwise, `false`.


### GetHashCode()

Returns the hash code for the current [[Nonce|Nonce Struct]].

    public override int GetHashCode()

#### Return Value

A 32-bit signed integer hash code.


### ToArray()

Copies the current [[Nonce|Nonce Struct]] to a new array of bytes.

    public byte[] ToArray()

#### Return Value

A new array of bytes containing a copy of the current nonce.


### ToString()

Returns a string representation of the current [[Nonce|Nonce Struct]].

    public override string ToString()

#### Return Value

A string representation of the current [[Nonce|Nonce Struct]].


## Operators


### Addition(Nonce, int)

Adds the specified value to the counter field of the specified [[Nonce|Nonce
Struct]].

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

Increments the counter field of the specified [[Nonce|Nonce Struct]] by 1.

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


### Xor(Nonce, ReadOnlySpan<byte>)

Returns a new [[Nonce|Nonce Struct]] by performing a bitwise exclusive Or (XOr)
operation on the specified [[Nonce|Nonce Struct]] and the specified span of
bytes.

    public static Nonce operator ^(
        Nonce nonce,
        ReadOnlySpan<byte> bytes)

#### Parameters

nonce
: The nonce to xor with the span of bytes.

bytes
: The span of bytes to xor with the nonce.

#### Return Value

The resulting nonce.

#### Exceptions

ArgumentException
: The length of the span of bytes is not equal to the size of the nonce.


## Thread Safety

All members of this type are thread safe. Members that appear to modify instance
state actually return a new instance initialized with the new value. As with any
other type, reading and writing to a shared variable that contains an instance
of this type must be protected by a lock to guarantee thread safety.


## See Also

* API Reference
    * [[AeadAlgorithm Class]]
