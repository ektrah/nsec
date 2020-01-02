using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class X25519PublicKeyFormatter : PublicKeyFormatter
    {
        public X25519PublicKeyFormatter(byte[] blobHeader) : base(
            crypto_scalarmult_curve25519_SCALARBYTES,
            blobHeader)
        {
        }

        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            out PublicKeyBytes publicKeyBytes)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_scalarmult_curve25519_SCALARBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            Unsafe.CopyBlockUnaligned(ref Unsafe.As<PublicKeyBytes, byte>(ref publicKeyBytes), ref Unsafe.AsRef(in span.GetPinnableReference()), crypto_scalarmult_curve25519_SCALARBYTES);
            Unsafe.Add(ref Unsafe.As<PublicKeyBytes, byte>(ref publicKeyBytes), crypto_scalarmult_curve25519_SCALARBYTES - 1) &= 0x7F;
        }

        protected override void Serialize(
            in PublicKeyBytes publicKeyBytes,
            Span<byte> span)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_scalarmult_curve25519_SCALARBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            Unsafe.CopyBlockUnaligned(ref span.GetPinnableReference(), ref Unsafe.As<PublicKeyBytes, byte>(ref Unsafe.AsRef(in publicKeyBytes)), crypto_scalarmult_curve25519_SCALARBYTES);
        }
    }
}
