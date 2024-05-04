using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class X25519PrivateKeyFormatter(byte[] blobHeader) : PrivateKeyFormatter(
        crypto_scalarmult_curve25519_SCALARBYTES,
        blobHeader)
    {
        protected override void Deserialize(
            ReadOnlySpan<byte> span,
            out SecureMemoryHandle? keyHandle,
            out PublicKeyBytes publicKeyBytes)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_scalarmult_curve25519_SCALARBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            keyHandle = SecureMemoryHandle.CreateFrom(span);
            publicKeyBytes = new PublicKeyBytes();

            int error = crypto_scalarmult_curve25519_base(
                ref publicKeyBytes,
                keyHandle);

            Debug.Assert(error == 0);
            Debug.Assert((publicKeyBytes[crypto_scalarmult_curve25519_SCALARBYTES - 1] & 0x80) == 0);
        }

        protected override void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span)
        {
            Debug.Assert(keyHandle.Size == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            keyHandle.CopyTo(span);
        }
    }
}
