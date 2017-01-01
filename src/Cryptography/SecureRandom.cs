using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public static class SecureRandom
    {
        public static byte[] GenerateBytes(
            int count)
        {
            if (!Sodium.TryInitialize())
                throw new InvalidOperationException();
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count == 0)
                return new byte[0];

            byte[] bytes = new byte[count];
            randombytes_buf(bytes, (IntPtr)bytes.Length);
            return bytes;
        }

        public static void GenerateBytes(
            Span<byte> bytes)
        {
            if (!Sodium.TryInitialize())
                throw new InvalidOperationException();
            if (bytes.Length == 0)
                return;

            randombytes_buf(ref bytes.DangerousGetPinnableReference(), (IntPtr)bytes.Length);
        }
    }
}
