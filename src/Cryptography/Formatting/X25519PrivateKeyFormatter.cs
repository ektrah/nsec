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

        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKeyBytes publicKeyBytes)
        {
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_scalarmult_curve25519_SCALARBYTES);

            owner = memoryPool.Rent(crypto_scalarmult_curve25519_SCALARBYTES);
            memory = owner.Memory.Slice(0, crypto_scalarmult_curve25519_SCALARBYTES);
            span.CopyTo(owner.Memory.Span);
            crypto_scalarmult_curve25519_base(out publicKeyBytes, in owner.Memory.Span.GetPinnableReference());

            Debug.Assert((Unsafe.Add(ref Unsafe.As<PublicKeyBytes, byte>(ref publicKeyBytes), crypto_scalarmult_curve25519_SCALARBYTES - 1) & 0x80) == 0);
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
