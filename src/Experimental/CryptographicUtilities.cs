using System;
using System.Runtime.CompilerServices;

namespace NSec.Experimental
{
    public static class CryptographicUtilities
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] Base64Decode(string base64)
        {
            return NSec.Experimental.Text.Base64.Decode(base64);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Base64Encode(ReadOnlySpan<byte> bytes)
        {
            return NSec.Experimental.Text.Base64.Encode(bytes);
        }

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
        public static byte[] HexDecode(string base16)
        {
            return NSec.Experimental.Text.Base16.Decode(base16);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string HexEncode(ReadOnlySpan<byte> bytes)
        {
            return NSec.Experimental.Text.Base16.Encode(bytes);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ZeroMemory(Span<byte> buffer)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
