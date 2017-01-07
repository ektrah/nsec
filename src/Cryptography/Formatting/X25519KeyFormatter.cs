using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal class X25519KeyFormatter : KeyFormatter
    {
        public X25519KeyFormatter(
            int keySize,
            byte[] blobHeader)
            : base(keySize, blobHeader)
        {
        }

        protected override Key Deserialize(
            Algorithm algorithm,
            KeyFlags flags,
            ReadOnlySpan<byte> span)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            byte[] publicKeyBytes = new byte[crypto_scalarmult_curve25519_SCALARBYTES];
            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(span.Length);
            handle.Import(span);
            crypto_scalarmult_curve25519_base(publicKeyBytes, handle);
            return new Key(algorithm, flags, handle, new PublicKey(algorithm, publicKeyBytes));
        }

        protected override void Serialize(
            SecureMemoryHandle key,
            Span<byte> span)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(span.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            key.Export(span);
        }
    }
}
