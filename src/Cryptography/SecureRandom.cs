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
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count == 0)
                return new byte[0];

            Sodium.Initialize();

            byte[] bytes = new byte[count];
            randombytes_buf(bytes, (UIntPtr)bytes.Length);
            return bytes;
        }

        public static void GenerateBytes(
            Span<byte> bytes)
        {
            if (bytes.Length == 0)
                return;

            Sodium.Initialize();

            randombytes_buf(ref bytes.DangerousGetPinnableReference(), (UIntPtr)bytes.Length);
        }
    }
}
