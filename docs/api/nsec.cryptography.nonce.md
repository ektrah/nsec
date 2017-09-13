# Nonce Struct

Represents a nonce for [[authenticated encryption|AeadAlgorithm Class]].

    public struct Nonce : IComparable<Nonce>, IEquatable<Nonce>

A nonce consists of two fields: a fixed field and a counter field. The counter
fields of successive nonces form a monotonically increasing sequence, when those
fields are regarded as unsigned integers in big-endian byte order. The length of
both the fixed field and the counter field must remain constant for all nonces
that are generated for a given key.


## [TOC] Summary


## Constants


### MaxSize

Represents the largest possible size of a nonce, in bytes.

    public const int MaxSize = 15;

This field is constant and read-only.


## Constructors


### Nonce()

Initializes a new instance of [[Nonce|Nonce Struct]] with a zero-length fixed
field and a zero-length counter field.

    public Nonce()


### Nonce(int)

Initializes a new instance of [[Nonce|Nonce Struct]] with a zero-length fixed
field and a counter field of the specified size. The counter field is
initialized to zero.

    public Nonce(
        int counterFieldSize)

#### Parameters

counterFieldSize
: The size of the counter field.

#### Exceptions

ArgumentOutOfRangeException
: `counterFieldSize` is less than 0 or greater than [[MaxSize|Nonce
    Struct#MaxSize]].


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

    public int CounterFieldSize { get; }

#### Property Value


### FixedFieldSize

    public int FixedFieldSize { get; }

#### Property Value


### Size

    public int Size { get; }

#### Property Value


## Static Methods


### TryAdd(Nonce, int)

    public static bool TryAdd(
        ref Nonce nonce,
        int addend)

#### Parameters

#### Return Value

#### Exceptions


### TryIncrement(Nonce)

    public static bool TryIncrement(
        ref Nonce nonce)

#### Parameters

#### Return Value

#### Exceptions


## Methods


### CompareTo(Nonce)

    public int CompareTo(
        Nonce other)

#### Parameters

#### Return Value

#### Exceptions


### CopyTo(Span<byte>)

    public int CopyTo(
        Span<byte> destination)

#### Parameters

#### Return Value

#### Exceptions


### Equals(Nonce)

    public bool Equals(
        Nonce other)

#### Parameters

#### Return Value

#### Exceptions


### Equals(object)

    public override bool Equals(
        object obj)

#### Parameters

#### Return Value

#### Exceptions


### GetHashCode()

    public override int GetHashCode()

#### Parameters

#### Return Value

#### Exceptions


### ToArray()

    public byte[] ToArray()

#### Parameters

#### Return Value

#### Exceptions


### ToString()

    public override string ToString()

#### Parameters

#### Return Value

#### Exceptions


## Operators


### Addition(Nonce, int)

    public static Nonce operator +(
        Nonce nonce,
        int addend)

#### Parameters

#### Return Value

#### Exceptions


### Equality(Nonce, Nonce)

    public static bool operator ==(
        Nonce left,
        Nonce right)

#### Parameters

#### Return Value

#### Exceptions


### GreaterThan(Nonce, Nonce)

    public static bool operator >(
        Nonce left,
        Nonce right)

#### Parameters

#### Return Value

#### Exceptions


### GreaterThanOrEqual(Nonce, Nonce)

    public static bool operator >=(
        Nonce left,
        Nonce right)

#### Parameters

#### Return Value

#### Exceptions


### Increment(Nonce)

    public static Nonce operator ++(
        Nonce nonce)

#### Parameters

#### Return Value

#### Exceptions


### Inequality(Nonce, Nonce)

    public static bool operator !=(
        Nonce left,
        Nonce right)

#### Parameters

#### Return Value

#### Exceptions


### LessThan(Nonce, Nonce)

    public static bool operator <(
        Nonce left,
        Nonce right)

#### Parameters

#### Return Value

#### Exceptions


### LessThanOrEqual(Nonce, Nonce)

    public static bool operator <=(
        Nonce left,
        Nonce right)

#### Parameters

#### Return Value

#### Exceptions


### Xor(Nonce, ReadOnlySpan<byte>)

    public static Nonce operator ^(
        Nonce nonce,
        ReadOnlySpan<byte> bytes)

#### Parameters

#### Return Value

#### Exceptions


## Thread Safety

All members of this type are thread safe. Members that appear to modify instance
state actually return a new instance initialized with the new value. As with any
other type, reading and writing to a shared variable that contains an instance
of this type must be protected by a lock to guarantee thread safety.


## See Also

* API Reference
    * [[AeadAlgorithm Class]]
