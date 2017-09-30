using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    internal sealed class DefaultRandomNumberGenerator : RandomNumberGenerator
    {
        public DefaultRandomNumberGenerator()
        {
        }

        private protected override void GenerateBytesCore(
            Span<byte> bytes)
        {
            randombytes_buf(ref bytes.DangerousGetPinnableReference(), (UIntPtr)bytes.Length);
        }
    }
}
