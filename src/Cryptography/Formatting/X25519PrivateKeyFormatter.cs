using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class X25519PrivateKeyFormatter : PrivateKeyFormatter
    {
        public X25519PrivateKeyFormatter(byte[] blobHeader) : base(
            crypto_scalarmult_curve25519_SCALARBYTES,
            blobHeader)
        {
        }

        protected override unsafe void Deserialize(
            ReadOnlySpan<byte> span,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKeyBytes publicKeyBytes)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_scalarmult_curve25519_SCALARBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            owner = memoryPool.Rent(crypto_scalarmult_curve25519_SCALARBYTES);
            memory = owner.Memory.Slice(0, crypto_scalarmult_curve25519_SCALARBYTES);
            span.CopyTo(owner.Memory.Span);

            fixed (PublicKeyBytes* q = &publicKeyBytes)
            fixed (byte* n = owner.Memory.Span)
            {
                int error = crypto_scalarmult_curve25519_base(q, n);

                Debug.Assert(error == 0);
                Debug.Assert((((byte*)q)[crypto_scalarmult_curve25519_SCALARBYTES - 1] & 0x80) == 0);
            }
        }

        protected override void Serialize(
            ReadOnlySpan<byte> privateKeyBytes,
            Span<byte> span)
        {
            Debug.Assert(privateKeyBytes.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            privateKeyBytes.CopyTo(span);
        }
    }
}
