using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Auto)]
    public ref struct SharedSecretCreationParameters
    {
        public KeyExportPolicies ExportPolicy;
    }
}
