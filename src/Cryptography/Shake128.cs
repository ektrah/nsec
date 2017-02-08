using System;
using static Interop.KeccakTiny;

namespace NSec.Cryptography
{
    public sealed class Shake128 : HashAlgorithm
    {
        public Shake128() : base(
            minHashSize: 0,
            defaultHashSize: 32,
            maxHashSize: int.MaxValue)
        {
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            shake128(
                ref hash.DangerousGetPinnableReference(),
                (ulong)hash.Length,
                ref data.DangerousGetPinnableReference(),
                (ulong)data.Length);
        }
    }
}
