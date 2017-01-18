# Key Class

Represents a symmetric key or an asymmetric key pair.

    public sealed class Key : IDisposable


## [TOC] Summary


## Constructors


### Key(Algorithm, KeyFlags)

Initializes a new instance of the [[Key|Key Class]] class with a random key.

    public Key(
        Algorithm algorithm,
        KeyFlags flags = KeyFlags.None)

#### Parameters

algorithm
: The algorithm for the key.

flags
: A bitwise combination of [[KeyFlags|KeyFlags Enum]] values that specifies
    the flags for the new key.

#### Exceptions

ArgumentNullException
: `algorithm` is null.

NotSupportedException
: The specified algorithm does not support keys.


## Properties


### Algorithm

Gets the algorithm for the key.

    public Algorithm Algorithm { get; }

#### Property value

An instance of the [[Algorithm|Algorithm Class]] class.


### Flags

Gets the flags for the key.

    public KeyFlags Flags { get; }

#### Property value

A bitwise combination of [[KeyFlags|KeyFlags Enum]] values that specifies the
flags for the key.


### PublicKey

Gets the public key if the current instance of the [[Key|Key Class]] class
represents a key pair.

    public PublicKey PublicKey { get; }

#### Property value

An instance of the [[PublicKey|PublicKey Class]] class if the current instance
of the [[Key|Key Class]] class represents a key pair; otherwise, `null`.


## Methods


### Create(Algorithm, KeyFlags)

Creates a new instance of the [[Key|Key Class]] class with a random key.

    public static Key Create(
        Algorithm algorithm,
        KeyFlags flags = KeyFlags.None)

#### Parameters

algorithm
: The algorithm for the key.

flags
: A bitwise combination of [[KeyFlags|KeyFlags Enum]] values that specifies
    the flags for the new key.

#### Exceptions

ArgumentNullException
: `algorithm` is null.

NotSupportedException
: The specified algorithm does not support keys.


### GetKeyBlobSize(Algorithm, KeyBlobFormat)

Gets the maximum size of a key BLOB for the specified algorithm and format.

    public static int? GetKeyBlobSize(
        Algorithm algorithm,
        KeyBlobFormat format)

#### Parameters

algorithm
: The algorithm for the key BLOB format.

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of a key BLOB.

#### Return value

The maximum key BLOB size if the specified format is supported by the algorithm;
otherwise, `null`.


### GetSupportedKeyBlobFormats(Algorithm)

    public static ReadOnlySpan<KeyBlobFormat> GetSupportedKeyBlobFormats(
        Algorithm algorithm)

Gets the key BLOB formats supported by the specified algorithm.

#### Parameters

algorithm
: The algorithm.

#### Return value

A span of [[KeyBlobFormat|KeyBlobFormat Enum]] values where each value specifies
a key BLOB format supported by the algorithm.


### Import(Algorithm, ReadOnlySpan<byte>, KeyBlobFormat, KeyFlags)

Imports the specified key BLOB in the specified format.

    public static Key Import(
        Algorithm algorithm,
        ReadOnlySpan<byte> blob,
        KeyBlobFormat format,
        KeyFlags flags = KeyFlags.None)

#### Parameters

algorithm
: The algorithm for the imported key.

blob
: The key BLOB to import.

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the key BLOB.

flags
: A bitwise combination of [[KeyFlags|KeyFlags Enum]] values that specifies
    the flags for the imported key.

#### Return value

A new instance of the [[Key|Key Class]] class that represents the imported key.

#### Exceptions

ArgumentNullException
: `algorithm` is null.

FormatException
: The key BLOB is not in the correct format or the format is not supported.

NotSupportedException
: The specified algorithm does not support importing keys.


### TryImport(Algorithm, ReadOnlySpan<byte>, KeyBlobFormat, KeyFlags, Key)

Attempts to import the specified key BLOB in the specified format.

    public static bool TryImport(
        Algorithm algorithm,
        ReadOnlySpan<byte> blob,
        KeyBlobFormat format,
        KeyFlags flags,
        out Key result)

#### Parameters

algorithm
: The algorithm for the imported key.

blob
: The key BLOB to import.

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the key BLOB.

flags
: A bitwise combination of [[KeyFlags|KeyFlags Enum]] values that specifies
    the flags for the imported key.

result
: When this method returns, contains a new instance of the [[Key|Key Class]]
    class that represents the imported key, or `null` if the import failed.

#### Return value

`true` if the import succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `algorithm` is null.

NotSupportedException
: The specified algorithm does not support importing keys.


### Dispose()

Securely erases the key and releases all resources used by the current instance
of the [[Key|Key Class]] class.

    public void Dispose();


### Export(KeyBlobFormat)

Exports the key as a BLOB in the specified format and returns it as an array
of bytes.

    public byte[] Export(
        KeyBlobFormat format)


#### Parameters

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the key BLOB.

#### Returns

A BLOB that contains the key in the specified format.

#### Exceptions

FormatException
: The algorithm for the key does not support the specified format.

InvalidOperationException
: The flags for the key do not allow the key to be exported.

NotSupportedException
: The algorithm for the key does not support exporting keys.

ObjectDisposedException
: The key has been disposed.


### Export(KeyBlobFormat, Span<byte>)

Exports the key as a BLOB in the specified format and writes it to the start
of the specified span of bytes.

    public int Export(
        KeyBlobFormat format,
        Span<byte> blob)

#### Parameters

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the key BLOB.

blob
: The span to fill with the key BLOB. The size of the span must be greater than
    or equal to `Key.GetKeyBlobSize(key.Algorithm, format)` where `key` is the
    key to export.
    
#### Returns

The actual number of bytes written to `blob`.

#### Exceptions

ArgumentException
: The length of `blob` is less than the value returned by
    [[GetKeyBlobSize|Key Class#GetKeyBlobSize(Algorithm, KeyBlobFormat)]]
    for the specified format.

FormatException
: The algorithm for the key does not support the specified format.

InvalidOperationException
: The flags for the key do not allow the key to be exported.

NotSupportedException
: The algorithm for the key does not support exporting keys.

ObjectDisposedException
: The key has been disposed.


## See also

* API Reference
    * [[Algorithm Class]]
    * [[KeyBlobFormat Enum]]
    * [[KeyFlags Enum]]
    * [[PublicKey Class]]
