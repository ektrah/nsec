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
        }

        protected override Key Deserialize(
            Algorithm algorithm,
            KeyFlags flags,
            ReadOnlySpan<byte> span)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            byte[] publicKeyBytes = new byte[crypto_sign_ed25519_PUBLICKEYBYTES];
            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(crypto_sign_ed25519_SECRETKEYBYTES);
            crypto_sign_ed25519_seed_keypair(publicKeyBytes, handle, ref span.DangerousGetPinnableReference());
            return new Key(algorithm, flags, handle, new PublicKey(algorithm, publicKeyBytes));
        }

        protected override void Serialize(
            Key key,
            Span<byte> span)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.Handle.Length == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            crypto_sign_ed25519_sk_to_seed(ref span.DangerousGetPinnableReference(), key.Handle);
        }
    }
}
