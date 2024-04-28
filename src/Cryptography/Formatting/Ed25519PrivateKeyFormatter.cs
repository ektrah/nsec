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
        protected unsafe override void Deserialize(
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

            fixed (PublicKeyBytes* pk = &publicKeyBytes)
            fixed (byte* seed_ = span)
            {
                int error = crypto_sign_ed25519_seed_keypair(pk, keyHandle, seed_);

                Debug.Assert(error == 0);
            }
        }

        protected unsafe override void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span)
        {
            Debug.Assert(keyHandle.Size == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            fixed (byte* seed_ = span)
            {
                int error = crypto_sign_ed25519_sk_to_seed(seed_, keyHandle);

                Debug.Assert(error == 0);
            }
        }
    }
}
