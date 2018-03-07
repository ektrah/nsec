using System;
using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Auto)]
    public struct KeyCreationParameters
    {
        public KeyExportPolicies ExportPolicy;
    }
}
