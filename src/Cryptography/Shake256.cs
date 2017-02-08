using System;
using static Interop.KeccakTiny;

namespace NSec.Cryptography
{
    public sealed class Shake256 : HashAlgorithm
    {
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
