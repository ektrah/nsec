using System;
using static Interop.KeccakTiny;

namespace NSec.Cryptography
{
    //
    //  SHA3-256
    //
    //      SHA-3 Permutation-Based Hash with a 256-bit message digest
    //
    //  References:
    //
    //      FIPS 202 - SHA-3 Standard: Permutation-Based Hash and
    //          Extendable-Output Functions
    //
    //  Parameters:
    //
    //      Input Size - The SHA-3 functions are defined on messages of any bit
    //          length, including the empty string.
    //
    //      Hash Size - 32 bytes (128 bits of security).
    //
    public sealed class Sha3_256 : HashAlgorithm
    {
        public Sha3_256() : base(
            minHashSize: 32,
            defaultHashSize: 32,
            maxHashSize: 32)
        {
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            sha3_256(
                ref hash.DangerousGetPinnableReference(),
                (ulong)hash.Length,
                ref data.DangerousGetPinnableReference(),
                (ulong)data.Length);
        }
    }
}
