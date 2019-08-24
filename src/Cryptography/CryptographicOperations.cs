using System;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography
{
    internal static class CryptographicOperations
    {
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static unsafe bool FixedTimeEquals(byte* left, byte* right, int length)
        {
            // NoOptimization because we want this method to be exactly as
            // non-short-circuiting as written. NoInlining because the
            // NoOptimization would get lost if the method got inlined.

            unchecked
            {
                int accum = 0;

                for (int i = 0; i < length; i++)
                {
                    accum |= left[i] - right[i];
                }

                return accum == 0;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void ZeroMemory(Span<byte> buffer)
        {
            // NoOptimize to prevent the optimizer from deciding this call is
            // unnecessary. NoInlining to prevent the inliner from forgetting
            // that the method was no-optimize.

            buffer.Clear();
        }
    }
}
