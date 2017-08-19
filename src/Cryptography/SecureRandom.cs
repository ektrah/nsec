using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public static class SecureRandom
    {
        public static byte[] GenerateBytes(
            int count)
        {
            if (count < 0)
            {
                throw Error.ArgumentOutOfRange_GenerateNegativeCount(nameof(count));
            }

            Sodium.Initialize();

            byte[] bytes = new byte[count];
            GenerateBytesCore(bytes);
            return bytes;
        }

        public static void GenerateBytes(
            Span<byte> bytes)
        {
            Sodium.Initialize();

            GenerateBytesCore(bytes);
        }

        internal static void GenerateBytesCore(
            Span<byte> bytes)
        {
            randombytes_buf(ref bytes.DangerousGetPinnableReference(), (UIntPtr)bytes.Length);
        }
    }
}
