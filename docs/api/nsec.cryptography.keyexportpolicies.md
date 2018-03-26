# KeyExportPolicies Enum

Specifies the key export policies for a [[key|Key Class]].

    [Flags]
    public enum KeyExportPolicies


## Members

None
: The private key cannot be exported.

AllowPlaintextArchiving
: The private key can be exported one time for archiving purposes.

AllowPlaintextExport
: The private key can be exported multiple times.


## See Also

* API Reference
    * [[Key Class]]
    * [[KeyCreationParameters Struct]]
