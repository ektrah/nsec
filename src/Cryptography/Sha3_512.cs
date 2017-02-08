using System;
using static Interop.KeccakTiny;

namespace NSec.Cryptography
{
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
