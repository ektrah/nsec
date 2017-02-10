using System;
using static Interop.KeccakTiny;

namespace NSec.Cryptography
{
    //
    //  SHA3-512
    //
    //      SHA-3 Permutation-Based Hash with a 512-bit message digest
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
    //      Hash Size - 64 bytes (256 bits of security).
    //
    public sealed class Sha3_512 : HashAlgorithm
    {
        public Sha3_512() : base(
            minHashSize: 32,
            defaultHashSize: 64,
            maxHashSize: 64)
        {
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            sha3_512(
                ref hash.DangerousGetPinnableReference(),
                (ulong)hash.Length,
                ref data.DangerousGetPinnableReference(),
                (ulong)data.Length);
        }
    }
}
