using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct IncrementalHashState
    {
        [FieldOffset(0)]
        internal crypto_generichash_blake2b_state blake2b;

        [FieldOffset(0)]
        internal crypto_hash_sha256_state sha256;

        [FieldOffset(0)]
        internal crypto_hash_sha512_state sha512;
    }
}
