using System;
using static Interop.KeccakTiny;

namespace NSec.Cryptography
{
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
