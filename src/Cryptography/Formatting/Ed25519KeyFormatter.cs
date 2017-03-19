using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal class Ed25519KeyFormatter : KeyFormatter
    {
        public Ed25519KeyFormatter(
            int keySize,
            byte[] blobHeader)
            : base(keySize, blobHeader)
        {
            Debug.Assert(keySize == crypto_sign_ed25519_SEEDBYTES);
        }

        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            publicKeyBytes = new byte[crypto_sign_ed25519_PUBLICKEYBYTES];
            SecureMemoryHandle.Alloc(crypto_sign_ed25519_SECRETKEYBYTES, out keyHandle);
            crypto_sign_ed25519_seed_keypair(publicKeyBytes, keyHandle, ref span.DangerousGetPinnableReference());
        }

        protected override void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            crypto_sign_ed25519_sk_to_seed(ref span.DangerousGetPinnableReference(), keyHandle);
        }
    }
}
