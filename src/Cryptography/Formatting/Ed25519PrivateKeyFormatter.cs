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

        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKeyBytes publicKeyBytes)
        {
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_sign_ed25519_PUBLICKEYBYTES);

            owner = memoryPool.Rent(crypto_sign_ed25519_SECRETKEYBYTES);
            memory = owner.Memory.Slice(0, crypto_sign_ed25519_SECRETKEYBYTES);

            int error = crypto_sign_ed25519_seed_keypair(
                out publicKeyBytes,
                out owner.Memory.Span.GetPinnableReference(),
                in span.GetPinnableReference());

            Debug.Assert(error == 0);
        }

        protected override void Serialize(
            ReadOnlySpan<byte> privateKeyBytes,
            Span<byte> span)
        {
            Debug.Assert(privateKeyBytes.Length == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(span.Length == crypto_sign_ed25519_SEEDBYTES);

            int error = crypto_sign_ed25519_sk_to_seed(
                ref span.GetPinnableReference(),
                in privateKeyBytes.GetPinnableReference());

            Debug.Assert(error == 0);
        }
    }
}
