using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal class X25519KeyFormatter : KeyFormatter
    {
        public X25519KeyFormatter(
            int keySize,
            byte[] blobHeader)
            : base(keySize, blobHeader)
        {
        }

        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            publicKeyBytes = new byte[crypto_scalarmult_curve25519_SCALARBYTES];
            SecureMemoryHandle.Alloc(span.Length, out keyHandle);
            keyHandle.Import(span);
            crypto_scalarmult_curve25519_base(publicKeyBytes, keyHandle);
        }

        protected override void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            keyHandle.Export(span);
        }
    }
}
