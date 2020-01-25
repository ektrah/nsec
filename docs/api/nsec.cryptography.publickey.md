# PublicKey Class

Represents a public key.

    public sealed class PublicKey : IEquatable<PublicKey>


## [TOC] Summary


## Properties


### Algorithm

Gets the algorithm for the public key.

    public Algorithm Algorithm { get; }

#### Property Value

An instance of the [[Algorithm|Algorithm Class]] class.


### Size

Gets the size of the public key.

    public int Size { get; }

#### Property Value

The public key size, in bytes.


## Static Methods


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

#### Return Value

A new instance of the [[PublicKey|PublicKey Class]] class that represents the
imported key.

#### Exceptions

ArgumentNullException
: `algorithm` is `null`.

ArgumentException
: The specified format is not supported by the specified algorithm.

FormatException
: The public key BLOB is not in the correct format.

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

#### Return Value

`true` if the public key BLOB was imported; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `algorithm` is null.

NotSupportedException
: The specified algorithm does not support importing public keys.


## Methods


### Equals(PublicKey?)

Indicates whether the current instance of the [[PublicKey|PublicKey Class]]
class is equal to another instance of the same type.

    public bool Equals(
        PublicKey? other)

#### Parameters

other
: An object to compare with this object.

#### Return Value

`true` if the current object is equal to the `other` parameter; otherwise,
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

#### Return Value

A BLOB that contains the public key in the specified format.

#### Exceptions

ArgumentException
: The algorithm for the public key does not support the specified format.

NotSupportedException
: The algorithm for the public key does not support exporting public keys.


### GetExportBlobSize(KeyBlobFormat)

Returns the BLOB size of the public key if it were exported in the specified
format.

    public int GetExportBlobSize(
        KeyBlobFormat format)

#### Parameters

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the public key BLOB.

#### Return Value

The size (in bytes) of the public key if it were exported as a BLOB in the
specified format.

#### Exceptions

ArgumentException
: The algorithm for the public key does not support the specified format.

NotSupportedException
: The algorithm for the public key does not support exporting public keys.


### GetHashCode()

Returns the hash code for the current [[PublicKey|PublicKey Class]] object.

    public override int GetHashCode()

#### Return Value

A 32-bit signed integer hash code.

#### Remarks

The [[PublicKey|PublicKey Class]] class overrides the [[GetHashCode|PublicKey
Class#GetHashCode()]] method so that [[PublicKey|PublicKey Class]] objects can
be used as elements of a HashSet<T> or keys of a Dictionary<TKey, TValue>. The
hash code is **not** a fingerprint that can be used to identify the public key.

The hash code returned may differ between NSec versions and platforms, such as
32-bit and 64-bit platforms.


### TryExport(KeyBlobFormat, Span<byte>, out int)

Exports the public key as a public key BLOB in the specified format and attempts
to fill the specified span of bytes with the BLOB.

    public bool TryExport(
        KeyBlobFormat format,
        Span<byte> blob,
        out int blobSize)

#### Parameters

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the public key BLOB.

blob
: The span to fill with the exported public key BLOB.
    The length of the span must be greater than or equal to
    `GetExportBlobSize(format)`.

blobSize
: When this method returns, contains the number of bytes written into the output
    span.

#### Return Value

`false` if there is not enough space in the output span to write the public key
BLOB; otherwise `true`.

#### Exceptions

ArgumentException
: The algorithm for the public key does not support the specified format.

NotSupportedException
: The algorithm for the public key does not support exporting public keys.


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
    * [[KeyBlobFormat Enum]]
