using System;
using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Auto)]
    public ref struct KeyCreationParameters
    {
        public KeyExportPolicies ExportPolicy;
    }
}
