using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct IncrementalMacState
    {
        [FieldOffset(0)]
        internal crypto_generichash_blake2b_state blake2b;

        [FieldOffset(0)]
        internal crypto_auth_hmacsha256_state hmacsha256;

        [FieldOffset(0)]
        internal crypto_auth_hmacsha512_state hmacsha512;
    }
}
