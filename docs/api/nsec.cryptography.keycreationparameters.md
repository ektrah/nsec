# KeyCreationParameters Struct

Contains parameters for the creation of a [[Key|Key Class]] instance.

    public struct KeyCreationParameters


## [TOC] Summary


## Constructors


### KeyCreationParameters()

Initializes a new instance of [[KeyCreationParameters|KeyCreationParameters
Struct]] with default values.

    public KeyCreationParameters()


## Fields


### ExportPolicy

Gets or sets the export policy for the key.

    public KeyExportPolicies ExportPolicy;

#### Field Value

A bitwise combination of [[KeyExportPolicies|KeyExportPolicies Enum]] values
that specifies the export policy for the key.

The default value is [[KeyExportPolicies.None|KeyExportPolicies Enum]].


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe.


## See Also

* API Reference
    * [[Key Class]]
    * [[KeyExportPolicies Enum]]
