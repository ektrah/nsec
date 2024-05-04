using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class X25519PublicKeyFormatter(byte[] blobHeader) : PublicKeyFormatter(
        crypto_scalarmult_curve25519_SCALARBYTES,
        blobHeader)
    {
        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            out PublicKeyBytes publicKeyBytes)
        {
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            publicKeyBytes = new PublicKeyBytes();
            span.CopyTo(publicKeyBytes);
            publicKeyBytes[crypto_scalarmult_curve25519_SCALARBYTES - 1] &= 0x7F;

            Debug.Assert((publicKeyBytes[crypto_scalarmult_curve25519_SCALARBYTES - 1] & 0x80) == 0);
        }

        protected override void Serialize(
            ref readonly PublicKeyBytes publicKeyBytes,
            Span<byte> span)
        {
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            publicKeyBytes[..crypto_scalarmult_curve25519_SCALARBYTES].CopyTo(span);
        }
    }
}
