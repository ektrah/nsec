# KeyExportPolicies Enum

Specifies the key export policies for a [[private or symmetric key|Key Class]] or a [[shared secret|SharedSecret Class]].

    [Flags]
    public enum KeyExportPolicies


## Members

None
: The key or shared secret cannot be exported.

AllowPlaintextArchiving
: The key or shared secret can be exported one time for archiving purposes.

AllowPlaintextExport
: The key or shared secret can be exported multiple times.


## See Also

* API Reference
    * [[Key Class]]
    * [[KeyCreationParameters Struct]]
    * [[SharedSecretCreationParameters Struct]]
