using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class Ed25519PrivateKeyFormatter : PrivateKeyFormatter
    {
        public Ed25519PrivateKeyFormatter(byte[] blobHeader) : base(
            crypto_sign_ed25519_SEEDBYTES,
            blobHeader)
        {
        }

        protected unsafe override void Deserialize(
            ReadOnlySpan<byte> span,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKeyBytes publicKeyBytes)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            owner = memoryPool.Rent(crypto_sign_ed25519_SECRETKEYBYTES);
            memory = owner.Memory.Slice(0, crypto_sign_ed25519_SECRETKEYBYTES);

            fixed (PublicKeyBytes* pk = &publicKeyBytes)
            fixed (byte* sk = owner.Memory.Span)
            fixed (byte* seed_ = span)
            {
                int error = crypto_sign_ed25519_seed_keypair(pk, sk, seed_);

                Debug.Assert(error == 0);
            }
        }

        protected unsafe override void Serialize(
            ReadOnlySpan<byte> privateKeyBytes,
            Span<byte> span)
        {
            Debug.Assert(privateKeyBytes.Length == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            fixed (byte* seed_ = span)
            fixed (byte* sk = privateKeyBytes)
            {
                int error = crypto_sign_ed25519_sk_to_seed(seed_, sk);

                Debug.Assert(error == 0);
            }
        }
    }
}
