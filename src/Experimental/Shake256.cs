using System;
using static NSec.Cryptography.Experimental.KeccakTiny;

namespace NSec.Cryptography.Experimental
{
    //
    //  SHAKE256
    //
    //      SHA-3 Extendable-Output Function with 256-bit security strength
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
    //      Hash Size - Any.
    //
    public sealed class Shake256 : HashAlgorithm
    {
        private static readonly Oid s_oid = new Oid(2, 16, 840, 1, 101, 3, 4, 2, 12);

        public Shake256() : base(
            minHashSize: 0,
            defaultHashSize: 64,
            maxHashSize: int.MaxValue)
        {
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            shake256(
                ref hash.DangerousGetPinnableReference(),
                (ulong)hash.Length,
                ref data.DangerousGetPinnableReference(),
                (ulong)data.Length);
        }
    }
}
