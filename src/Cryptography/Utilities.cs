using System;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography
{
    internal static class Utilities
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToBigEndian(uint value)
        {
            if (BitConverter.IsLittleEndian)
            {
                return unchecked(
                    (value << 24) |
                    ((value & 0xFF00) << 8) |
                    ((value & 0xFF0000) >> 8) |
                    (value >> 24));
            }
            else
            {
                return value;
            }
        }
    }
}
