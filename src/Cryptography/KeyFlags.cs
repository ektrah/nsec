using System;

namespace NSec.Cryptography
{
    [Flags]
    public enum KeyFlags
    {
        // Secret key can not be exported
        None = 0,

        // Secret key can be exported multiple times
        AllowExport = 1,

        // Secret key can be exported one time
        AllowArchiving = 2,
    }
}
