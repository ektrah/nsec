# SharedSecret Class

Represents the output of a [[key agreement|KeyAgreementAlgorithm Class]] and the
input for a [[key derivation|KeyDerivationAlgorithm Class]].

    public sealed class SharedSecret : IDisposable


## [TOC] Summary


## Properties


### ExportPolicy

Gets the export policy for the shared secret.

    public KeyExportPolicies ExportPolicy { get; }

#### Property Value

A bitwise combination of [[KeyExportPolicies|KeyExportPolicies Enum]] values
that specifies the export policy for the shared secret.


### Size

Gets the size of the shared secret.

    public int Size { get; }

#### Property Value

The size, in bytes, of the shared secret.


## Static Methods


### Import(ReadOnlySpan<byte>, SharedSecretBlobFormat, in SharedSecretCreationParameters)

Imports the specified shared secret BLOB in the specified format.

    public static SharedSecret Import(
        ReadOnlySpan<byte> blob,
        SharedSecretBlobFormat format,
        in SharedSecretCreationParameters creationParameters = default)

#### Parameters

blob
: The shared secret BLOB to import.

format
: One of the [[SharedSecretBlobFormat|SharedSecretBlobFormat Enum]] values that specifies the
    format of the shared secret BLOB.

creationParameters
: A [[SharedSecretCreationParameters|SharedSecretCreationParameters Struct]] value that specifies
    advanced parameters for the creation of the [[SharedSecret|SharedSecret Class]] instance.

#### Return Value

A new instance of the [[SharedSecret|SharedSecret Class]] class that represents the imported shared secret.

#### Exceptions

ArgumentException
: The specified format is not supported.

FormatException
: The shared secret BLOB is not in the correct format.


### TryImport(ReadOnlySpan<byte>, SharedSecretBlobFormat, out SharedSecret?, in SharedSecretCreationParameters)

Attempts to import the specified shared secret BLOB in the specified format.

    public static bool TryImport(
        ReadOnlySpan<byte> blob,
        SharedSecretBlobFormat format,
        out SharedSecret? result,
        in SharedSecretCreationParameters creationParameters = default)

#### Parameters

blob
: The shared secret BLOB to import.

format
: One of the [[SharedSecretBlobFormat|SharedSecretBlobFormat Enum]] values that specifies the
    format of the shared secret BLOB.

result
: When this method returns, contains a new instance of the [[SharedSecret|SharedSecret Class]]
    class that represents the imported shared secret, or `null` if the import fails.

creationParameters
: A [[SharedSecretCreationParameters|SharedSecretCreationParameters Struct]] value that specifies
    advanced parameters for the creation of the [[SharedSecret|SharedSecret Class]] instance.

#### Return Value

`true` if the import succeeds; otherwise, `false`.

#### Exceptions

ArgumentException
: The specified format is not supported.


## Methods


### Dispose()

Securely erases the shared secret from memory and releases all resources used by
the current instance of the [[SharedSecret|SharedSecret Class]] class.

    public void Dispose()


### Export(SharedSecretBlobFormat)

Exports the shared secret as a BLOB in the specified format and returns it as an array
of bytes.

    public byte[] Export(
        SharedSecretBlobFormat format)

#### Parameters

format
: One of the [[SharedSecretBlobFormat|SharedSecretBlobFormat Enum]] values that specifies the
    format of the shared secret BLOB.

#### Return Value

A BLOB that contains the sharedf secret in the specified format.

#### Exceptions

InvalidOperationException
: The export policy for the shared secret does not allow the shared secret to be exported.

ObjectDisposedException
: The shared secret has been disposed.


### GetExportBlobSize(SharedSecretBlobFormat)

Returns the BLOB size of the shared secret if it were exported in the specified format.

    public int GetExportBlobSize(
        SharedSecretBlobFormat format)

#### Parameters

format
: One of the [[SharedSecretBlobFormat|SharedSecretBlobFormat Enum]] values that specifies the
    format of the shared secret BLOB.

#### Return Value

The size (in bytes) of the shared secret if it were exported as a BLOB in the specified
format.

#### Exceptions

ObjectDisposedException
: The shared secret has been disposed.


### TryExport(SharedSecretBlobFormat, Span<byte>, out int)

Exports the specified shared secret BLOB in the specified format and attempts to fill the
specified span of bytes with the BLOB.

    public bool TryExport(
        SharedSecretBlobFormat format,
        Span<byte> blob,
        out int blobSize)

#### Parameters

format
: One of the [[SharedSecretBlobFormat|SharedSecretBlobFormat Enum]] values that specifies the
    format of the shared secret BLOB.

blob
: The span to fill with the exported shared secret BLOB.
    The length of the span must be greater than or equal to
    `GetExportBlobSize(format)`.

blobSize
: When this method returns, contains the number of bytes written into the output
    span.

#### Return Value

`false` if there is not enough space in the output span to write the shared secret BLOB;
otherwise `true`.

#### Exceptions

InvalidOperationException
: The export policy for the shared secret does not allow the shared secret to be exported.

ObjectDisposedException
: The shared secret has been disposed.


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe.


## See Also

* API Reference
    * [[KeyAgreementAlgorithm Class]]
    * [[KeyDerivationAlgorithm Class]]
    * [[KeyDerivationAlgorithm2 Class]]
    * [[SharedSecretBlobFormat Enum]]
    * [[SharedSecretCreationParameters Struct]]
