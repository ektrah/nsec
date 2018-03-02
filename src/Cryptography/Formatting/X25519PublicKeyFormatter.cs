using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class X25519PublicKeyFormatter : PublicKeyFormatter
    {
        public X25519PublicKeyFormatter(
            int keySize,
            byte[] blobHeader)
            : base(keySize, blobHeader)
        {
            Debug.Assert(keySize == crypto_scalarmult_curve25519_SCALARBYTES);
        }

        protected override byte[] Deserialize(
            ReadOnlySpan<byte> span)
        {
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            byte[] publicKeyBytes = span.ToArray();
            publicKeyBytes[publicKeyBytes.Length - 1] &= 0x7F;
            return publicKeyBytes;
        }

        protected override void Serialize(
            ReadOnlySpan<byte> publicKeyBytes,
            Span<byte> span)
        {
            Debug.Assert(publicKeyBytes.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            publicKeyBytes.CopyTo(span);
        }
    }
}
