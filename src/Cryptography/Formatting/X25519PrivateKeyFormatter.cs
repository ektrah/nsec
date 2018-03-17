using System;
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
            out SecureMemoryHandle keyHandle,
            out PublicKeyBytes publicKeyBytes)
        {
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_scalarmult_curve25519_SCALARBYTES);

            SecureMemoryHandle.Import(span, out keyHandle);
            crypto_scalarmult_curve25519_base(out publicKeyBytes, keyHandle);

            Debug.Assert((Unsafe.Add(ref Unsafe.As<PublicKeyBytes, byte>(ref publicKeyBytes), crypto_scalarmult_curve25519_SCALARBYTES - 1) & 0x80) == 0);
        }

        protected override void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            keyHandle.Export(span);
        }
    }
}
