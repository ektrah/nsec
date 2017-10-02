using System;

namespace NSec.Cryptography
{
    [Flags]
    public enum KeyExportPolicies
    {
        // Secret key can not be exported
        None = 0,

        // Secret key can be exported multiple times
        AllowPlaintextExport = 1,

        // Secret key can be exported one time
        AllowPlaintextArchiving = 2,
    }
}
