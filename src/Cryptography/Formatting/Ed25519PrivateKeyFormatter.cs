using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class Ed25519PrivateKeyFormatter(byte[] blobHeader) : PrivateKeyFormatter(
        crypto_sign_ed25519_SEEDBYTES,
        blobHeader)
    {
        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            out SecureMemoryHandle? keyHandle,
            out PublicKeyBytes publicKeyBytes)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            keyHandle = SecureMemoryHandle.Create(crypto_sign_ed25519_SECRETKEYBYTES);
            publicKeyBytes = new PublicKeyBytes();

            int error = crypto_sign_ed25519_seed_keypair(
                ref publicKeyBytes,
                keyHandle,
                span);

            Debug.Assert(error == 0);
        }

        protected override void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span)
        {
            Debug.Assert(keyHandle.Size == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            int error = crypto_sign_ed25519_sk_to_seed(
                span,
                keyHandle);

            Debug.Assert(error == 0);
        }
    }
}
