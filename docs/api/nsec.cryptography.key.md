# Key Class

Represents a symmetric key or asymmetric key pair.

    public sealed class Key : IDisposable


## [TOC] Summary


## Constructors


### Key(Algorithm, in KeyCreationParameters)

Initializes a new instance of the [[Key|Key Class]] class with a random key.

    public Key(
        Algorithm algorithm,
        in KeyCreationParameters creationParameters = default)

#### Parameters

algorithm
: The algorithm for the key.

creationParameters
: A [[KeyCreationParameters|KeyCreationParameters Struct]] value that specifies
    advanced parameters for the creation of the [[Key|Key Class]] instance.

#### Exceptions

ArgumentNullException
: `algorithm` is `null`.

NotSupportedException
: The specified algorithm does not use keys.

#### Remarks

This constructor is a shortcut for
[[RandomGenerator.Default.GenerateKey(Algorithm, in
KeyCreationParameters)|RandomGenerator Class#GenerateKey(Algorithm, in
KeyCreationParameters)]].


## Properties


### Algorithm

Gets the algorithm for the key.

    public Algorithm Algorithm { get; }

#### Property Value

An instance of the [[Algorithm|Algorithm Class]] class.


### ExportPolicy

Gets the export policy for the key.

    public KeyExportPolicies ExportPolicy { get; }

#### Property Value

A bitwise combination of [[KeyExportPolicies|KeyExportPolicies Enum]] values
that specifies the export policy for the key.

### PublicKey

Gets the public key if the current instance of the [[Key|Key Class]] class
represents a key pair.

    public PublicKey PublicKey { get; }

#### Property Value

An instance of the [[PublicKey|PublicKey Class]] class if the current instance
of the [[Key|Key Class]] class represents a key pair; otherwise, `null`.


## Static Methods


### Create(Algorithm, in KeyCreationParameters)

Creates a new instance of the [[Key|Key Class]] class with a random key.

    public static Key Create(
        Algorithm algorithm,
        in KeyCreationParameters creationParameters = default)

#### Parameters

algorithm
: The algorithm for the key.

creationParameters
: A [[KeyCreationParameters|KeyCreationParameters Struct]] value that specifies
    advanced parameters for the creation of the [[Key|Key Class]] instance.

#### Return Value

A new instance of the [[Key|Key Class]] class that represents the new key.

#### Exceptions

ArgumentNullException
: `algorithm` is `null`.

NotSupportedException
: The specified algorithm does not use keys.

#### Remarks

This method is a shortcut for
[[RandomGenerator.Default.GenerateKey(Algorithm, in
KeyCreationParameters)|RandomGenerator Class#GenerateKey(Algorithm, in
KeyCreationParameters)]].


### Import(Algorithm, ReadOnlySpan<byte>, KeyBlobFormat, in KeyCreationParameters)

Imports the specified key BLOB in the specified format.

    public static Key Import(
        Algorithm algorithm,
        ReadOnlySpan<byte> blob,
        KeyBlobFormat format,
        in KeyCreationParameters creationParameters = default)

#### Parameters

algorithm
: The algorithm for the imported key.

blob
: The key BLOB to import.

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the key BLOB.

creationParameters
: A [[KeyCreationParameters|KeyCreationParameters Struct]] value that specifies
    advanced parameters for the creation of the [[Key|Key Class]] instance.

#### Return Value

A new instance of the [[Key|Key Class]] class that represents the imported key.

#### Exceptions

ArgumentNullException
: `algorithm` is `null`.

ArgumentException
: The specified format is not supported by the specified algorithm.

FormatException
: The key BLOB is not in the correct format.

NotSupportedException
: The specified algorithm does not support importing keys.


### TryImport(Algorithm, ReadOnlySpan<byte>, KeyBlobFormat, out Key, in KeyCreationParameters)

Attempts to import the specified key BLOB in the specified format.

    public static bool TryImport(
        Algorithm algorithm,
        ReadOnlySpan<byte> blob,
        KeyBlobFormat format,
        out Key result,
        in KeyCreationParameters creationParameters = default)

#### Parameters

algorithm
: The algorithm for the imported key.

blob
: The key BLOB to import.

format
: One of the [[KeyBlobFormat|KeyBlobFormat Enum]] values that specifies the
    format of the key BLOB.

result
: When this method returns, contains a new instance of the [[Key|Key Class]]
    class that represents the imported key, or `null` if the import fails.

creationParameters
: A [[KeyCreationParameters|KeyCreationParameters Struct]] value that specifies
    advanced parameters for the creation of the [[Key|Key Class]] instance.

#### Return Value

`true` if the import succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `algorithm` is `null`.

ArgumentException
: The specified format is not supported by the specified algorithm.

NotSupportedException
: The specified algorithm does not support importing keys.


## Methods


### Dispose()

Securely erases the key from memory and releases all resources used by the
current instance of the [[Key|Key Class]] class.

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

#### Return Value

A BLOB that contains the key in the specified format.

#### Exceptions

ArgumentException
: The algorithm for the key does not support the specified format.

InvalidOperationException
: The export policy for the key do not allow the key to be exported.

NotSupportedException
: The algorithm for the key does not support exporting keys.

ObjectDisposedException
: The key has been disposed.


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe.


## See Also

* API Reference
    * [[Algorithm Class]]
    * [[KeyBlobFormat Enum]]
    * [[KeyCreationParameters Struct]]
    * [[KeyExportPolicies Enum]]
    * [[PublicKey Class]]
