using System;
using System.Linq;

namespace NSec.Cryptography
{
    internal static class Extensions
    {
        public static bool BlockEquals(
            this ReadOnlySpan<byte> first,
            ReadOnlySpan<byte> second)
        {
            return first.ToArray().SequenceEqual(second.ToArray()); // TODO: use ReadOnlySpan<T>.BlockEquals
        }
    }
}
