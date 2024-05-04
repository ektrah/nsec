using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class Ed25519PublicKeyFormatter(byte[] blobHeader) : PublicKeyFormatter(
        crypto_sign_ed25519_PUBLICKEYBYTES,
        blobHeader)
    {
        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            out PublicKeyBytes publicKeyBytes)
        {
            Debug.Assert(span.Length == crypto_sign_ed25519_PUBLICKEYBYTES);

            publicKeyBytes = new PublicKeyBytes();
            span.CopyTo(publicKeyBytes);
        }

        protected override void Serialize(
            ref readonly PublicKeyBytes publicKeyBytes,
            Span<byte> span)
        {
            Debug.Assert(span.Length == crypto_sign_ed25519_PUBLICKEYBYTES);

            publicKeyBytes[..crypto_sign_ed25519_PUBLICKEYBYTES].CopyTo(span);
        }
    }
}
