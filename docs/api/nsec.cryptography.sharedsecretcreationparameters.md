# SharedSecretCreationParameters Struct

Contains parameters for the creation of a [[SharedSecret|SharedSecret Class]]
instance.

    public ref struct SharedSecretCreationParameters


## [TOC] Summary


## Constructors


### SharedSecretCreationParameters()

Initializes a new instance of
[[SharedSecretCreationParameters|SharedSecretCreationParameters Struct]] with
default values.

    public SharedSecretCreationParameters()


## Fields


### ExportPolicy

Gets or sets the export policy for the shared secret.

    public KeyExportPolicies ExportPolicy;

#### Field Value

A bitwise combination of [[KeyExportPolicies|KeyExportPolicies Enum]] values
that specifies the export policy for the shared secret.

The default value is [[KeyExportPolicies.None|KeyExportPolicies Enum]].


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe.


## See Also

* API Reference
    * [[SharedSecret Class]]
    * [[KeyExportPolicies Enum]]
