using System;
using System.Buffers;
using System.Runtime.InteropServices;
using NSec.Cryptography.Buffers;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Auto)]
    public ref struct KeyCreationParameters
    {
        public KeyExportPolicies ExportPolicy;

        internal readonly MemoryPool<byte> GetMemoryPool()
        {
            return SecureMemoryPool<byte>.Shared;
        }
    }
}
