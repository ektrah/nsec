using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class Ed25519PublicKeyFormatter : PublicKeyFormatter
    {
        public Ed25519PublicKeyFormatter(byte[] blobHeader) : base(
            crypto_sign_ed25519_PUBLICKEYBYTES,
            blobHeader)
        {
        }

        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            out PublicKeyBytes publicKeyBytes)
        {
            Debug.Assert(span.Length == crypto_sign_ed25519_PUBLICKEYBYTES);
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_sign_ed25519_PUBLICKEYBYTES);

            Unsafe.CopyBlockUnaligned(ref Unsafe.As<PublicKeyBytes, byte>(ref publicKeyBytes), ref Unsafe.AsRef(in span.GetPinnableReference()), crypto_sign_ed25519_PUBLICKEYBYTES);
        }

        protected override void Serialize(
            in PublicKeyBytes publicKeyBytes,
            Span<byte> span)
        {
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_sign_ed25519_PUBLICKEYBYTES);
            Debug.Assert(span.Length == crypto_sign_ed25519_PUBLICKEYBYTES);

            Unsafe.CopyBlockUnaligned(ref span.GetPinnableReference(), ref Unsafe.As<PublicKeyBytes, byte>(ref Unsafe.AsRef(in publicKeyBytes)), crypto_sign_ed25519_PUBLICKEYBYTES);
        }
    }
}
