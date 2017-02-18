# PublicKey Class

Represents a public key.

    public sealed class PublicKey : IEquatable<PublicKey>


## [TOC] Summary


## Properties


### Algorithm

Gets the algorithm for the public key.

    public Algorithm Algorithm { get; }

#### Property value

An instance of the [[Algorithm|Algorithm Class]] class.


## Methods


### Import(Algorithm, ReadOnlySpan<byte>, KeyBlobFormat)

Imports the specified public key BLOB in the specified format.

    public static PublicKey Import(
        Algorithm algorithm,
        ReadOnlySpan<byte> blob,
        KeyBlobFormat format)

#### Parameters

algorithm
: The algorithm for the imported public key.

blob
: The public key BLOB to import.

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the public key BLOB.

#### Return value

A new instance of the [[PublicKey|PublicKey Class]] class that represents the
imported key.

#### Exceptions

ArgumentNullException
: `algorithm` is `null`.

FormatException
: The public key BLOB is not in the correct format or the format is not
    supported by the specified algorithm.

NotSupportedException
: The specified algorithm does not support importing public keys.


### TryImport(Algorithm, ReadOnlySpan<byte>, KeyBlobFormat, out PublicKey)

Attempts to import the specified public key BLOB in the specified format.

    public static bool TryImport(
        Algorithm algorithm,
        ReadOnlySpan<byte> blob,
        KeyBlobFormat format,
        out PublicKey result)

#### Parameters

algorithm
: The algorithm for the imported public key.

blob
: The public key BLOB to import.

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the public key BLOB.

result
: When this method returns, contains a new instance of the
    [[PublicKey|PublicKey Class]] class that represents the imported public key,
    or `null` if the import failed.

#### Return value

`true` if the public key BLOB was imported; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `algorithm` is null.

NotSupportedException
: The specified algorithm does not support importing public keys.


### Equals(PublicKey)

Indicates whether the current instance of the [[PublicKey|PublicKey Class]]
class is equal to another instance of the same type.

    public bool Equals(
        PublicKey other)

#### Parameters

other
: An object to compare with this object.

#### Returns

`true` if the current object is equal to the `other` parameter; otherwise,
`false`.


### Equals(object)

Indicates whether the current instance of the [[PublicKey|PublicKey Class]]
class is equal to the specified object.

    public override bool Equals(
        object obj)

#### Parameters

obj
: An object to compare with this object.

#### Returns

`true` if the current object is equal to the `obj` parameter; otherwise,
`false`.


### Export(KeyBlobFormat)

Exports the public key as a BLOB in the specified format and returns it as an
array of bytes.

    public byte[] Export(
        KeyBlobFormat format)

#### Parameters

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the public key BLOB.

#### Returns

A BLOB that contains the public key in the specified format.

#### Exceptions

FormatException
: The algorithm for the public key does not support the specified format.

NotSupportedException
: The algorithm for the public key does not support exporting public keys.


### Export(KeyBlobFormat, Span<byte>)

Exports the public key as a BLOB in the specified format and writes it to the start
of the specified span of bytes.

    public int Export(
        KeyBlobFormat format,
        Span<byte> blob)

#### Parameters

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the public key BLOB.

blob
: The span to fill with the public key BLOB.

#### Returns

The actual number of bytes written to `blob`.

#### Exceptions

ArgumentException
: The length of `blob` is less than the size of the key BLOB. The maximum BLOB
    size can be determined using the
    [[GetKeyBlobSize|Key Class#GetKeyBlobSize(Algorithm, KeyBlobFormat)]]
    method.

FormatException
: The algorithm for the public key does not support the specified format.

NotSupportedException
: The algorithm for the public key does not support exporting public keys.


### GetHashCode()

Returns the hash code for the current [[PublicKey|PublicKey Class]] object.

    public override int GetHashCode()

#### Returns

A 32-bit signed integer hash code.

#### Remarks

The [[PublicKey|PublicKey Class]] class overrides the [[GetHashCode|PublicKey
Class#GetHashCode()]] method so that [[PublicKey|PublicKey Class]] objects can
be used as elements of a HashSet<T> or keys of a Dictionary<TKey, TValue>. The
hash code is not a fingerprint that can be used to identify the public key.


## See also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
    * [[KeyBlobFormat Enum]]
