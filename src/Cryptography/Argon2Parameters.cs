using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Auto)]
    public struct Argon2Parameters
    {
        public int DegreeOfParallelism;
        public long MemorySize;
        public long NumberOfPasses;

        [SuppressMessage("Performance", "CA1822")]
        public readonly int Version => 0x13; // copied from libsodium/crypto_pwhash/argon2/argon2-core.h
    }
}
