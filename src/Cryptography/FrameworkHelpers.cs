using System;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography
{
    internal static class FrameworkHelpers
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
#if NETSTANDARD2_0
            return FixedTimeEqualsImpl(left, right);
#else
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left, right);
#endif
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool FixedTimeEqualsImpl(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.

            if (left.Length != right.Length)
            {
                return false;
            }

            int length = left.Length;
            int accum = 0;

            for (int i = 0; i < length; i++)
            {
                accum |= left[i] - right[i];
            }

            return accum == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ZeroMemory(Span<byte> buffer)
        {
#if NETSTANDARD2_0
            ZeroMemoryImpl(buffer);
#else
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
#endif
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static void ZeroMemoryImpl(Span<byte> buffer)
        {
            // NoOptimize to prevent the optimizer from deciding this call is unnecessary
            // NoInlining to prevent the inliner from forgetting that the method was no-optimize
            buffer.Clear();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Fill(Span<byte> seed)
        {
#if NETSTANDARD2_0
            unsafe
            {
                fixed (byte* buf = seed)
                {
                    Interop.Libsodium.randombytes_buf(buf, (nuint)seed.Length);
                }
            }
#else
            System.Security.Cryptography.RandomNumberGenerator.Fill(seed);
#endif
        }
    }
}
