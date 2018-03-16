using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  HMAC-SHA-256
    //
    //      Hashed Message Authentication Code (HMAC) based on SHA-256
    //
    //  References:
    //
    //      RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
    //
    //      RFC 6234 - US Secure Hash Algorithms (SHA and SHA-based HMAC and
    //          HKDF)
    //
    //      RFC 4231 - Identifiers and Test Vectors for HMAC-SHA-224,
    //          HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
    //
    //  Parameters:
    //
    //      Key Size - The key for HMAC-SHA-256 can be of any length. A length
    //          less than L=32 bytes (the output length of SHA-256) is strongly
    //          discouraged. Keys longer than L do not significantly increase
    //          the function strength.
    //
    //      MAC Size - 32 bytes. The output can be truncated to 16 bytes
    //          (128 bits of security).
    //
    public sealed class HmacSha256 : MacAlgorithm
    {
        private static readonly NSecKeyFormatter s_nsecKeyFormatter = new NSecKeyFormatter(crypto_hash_sha256_BYTES, int.MaxValue, new byte[] { 0xDE, 0x33, 0x46, 0xDE });

        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter(crypto_hash_sha256_BYTES, int.MaxValue);

        private static int s_selfTest;

        public HmacSha256() : base(
            minKeySize: crypto_hash_sha256_BYTES,
            defaultKeySize: crypto_hash_sha256_BYTES,
            maxKeySize: int.MaxValue,
            minMacSize: 16,
            defaultMacSize: crypto_auth_hmacsha256_BYTES,
            maxMacSize: crypto_auth_hmacsha256_BYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            publicKeyBytes = null;
            SecureMemoryHandle.Import(seed, out keyHandle);
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_hash_sha256_BYTES;
        }

        internal override bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        private protected override void MacCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(mac.Length <= crypto_auth_hmacsha256_BYTES);

            // crypto_auth_hmacsha256 requires a key with a length of exactly
            // crypto_auth_hmacsha256_KEYBYTES. crypto_auth_hmacsha256_init
            // accepts a key of arbitrary length. So we use _init here.

            // crypto_auth_hmacsha256_init hashes the key if it is larger than
            // the block size.

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, keyHandle, (UIntPtr)keyHandle.Length);
            crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(data), (ulong)data.Length);

            // crypto_auth_hmacsha256_final expects an output buffer with a size
            // of exactly crypto_auth_hmacsha256_BYTES, so we need to copy when
            // a truncated output is requested.

            if (mac.Length == crypto_auth_hmacsha256_BYTES)
            {
                crypto_auth_hmacsha256_final(ref state, ref MemoryMarshal.GetReference(mac));
            }
            else
            {
                Span<byte> temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];
                crypto_auth_hmacsha256_final(ref state, ref MemoryMarshal.GetReference(temp));
                temp.Slice(0, mac.Length).CopyTo(mac);
            }
        }

        private protected override bool TryVerifyCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(mac.Length <= crypto_auth_hmacsha256_BYTES);

            // crypto_auth_hmacsha256_verify does not support truncated HMACs,
            // so we calculate the MAC ourselves and call sodium_memcmp to
            // compare the expected MAC with the actual MAC.

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, keyHandle, (UIntPtr)keyHandle.Length);
            crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(data), (ulong)data.Length);
            crypto_auth_hmacsha256_final(ref state, ref MemoryMarshal.GetReference(temp));

            int result = sodium_memcmp(in MemoryMarshal.GetReference(temp), in MemoryMarshal.GetReference(mac), (UIntPtr)mac.Length);

            return result == 0;
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha256_bytes() != (UIntPtr)crypto_auth_hmacsha256_BYTES) ||
                (crypto_auth_hmacsha256_keybytes() != (UIntPtr)crypto_auth_hmacsha256_KEYBYTES) ||
                (crypto_auth_hmacsha256_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha256_state>()))
            {
                throw Error.Cryptographic_InitializationFailed(8933.ToString("X"));
            }
        }
    }
}
