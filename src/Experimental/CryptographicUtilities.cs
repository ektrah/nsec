using System;
using System.Runtime.CompilerServices;

namespace NSec.Experimental
{
    public static class CryptographicUtilities
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void FillRandomBytes(Span<byte> data)
        {
            System.Security.Cryptography.RandomNumberGenerator.Fill(data);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left, right);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ZeroMemory(Span<byte> buffer)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
