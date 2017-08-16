using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
        private const int SHA256HashSize = 32; // "L" in RFC 2104
        private const int SHA256MessageBlockSize = 64; // "B" in RFC 2104

        private static readonly NSecKeyFormatter s_nsecKeyFormatter = new NSecKeyFormatter(SHA256HashSize, int.MaxValue, new byte[]
        {
            0xDE, 0x33, 0x46, 0xDE
        });

        private static readonly Oid s_oid = new Oid(1, 2, 840, 113549, 2, 9);

        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter(SHA256HashSize, int.MaxValue);

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public HmacSha256() : base(
            minKeySize: SHA256HashSize,
            defaultKeySize: SHA256HashSize,
            maxKeySize: int.MaxValue,
            minMacSize: 16,
            defaultMacSize: crypto_auth_hmacsha256_BYTES,
            maxMacSize: crypto_auth_hmacsha256_BYTES)
        {
            if (!s_selfTest.Value)
                throw Error.Cryptographic_InitializationFailed();
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(seed.Length, out keyHandle);
            keyHandle.Import(seed);
        }

        internal override int GetDefaultSeedSize()
        {
            return SHA256HashSize;
        }

        internal override void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(mac.Length <= crypto_auth_hmacsha256_BYTES);

            // crypto_auth_hmacsha256_init accepts a key of arbitrary length,
            // while crypto_auth_hmacsha256 requires a key whose length is
            // exactly crypto_auth_hmacsha256_KEYBYTES. So we use _init here.

            // crypto_auth_hmacsha256_init hashes the key if it is larger than
            // the block size.

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, keyHandle, (UIntPtr)keyHandle.Length);
            crypto_auth_hmacsha256_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);

            // crypto_auth_hmacsha256_final expects an output buffer with a size
            // of exactly crypto_auth_hmacsha256_BYTES, so we need to copy when
            // a truncated output is requested.

            if (mac.Length == crypto_auth_hmacsha256_BYTES)
            {
                crypto_auth_hmacsha256_final(ref state, ref mac.DangerousGetPinnableReference());
            }
            else
            {
                Span<byte> temp;
                try
                {
                    unsafe
                    {
                        byte* pointer = stackalloc byte[crypto_auth_hmacsha256_BYTES];
                        temp = new Span<byte>(pointer, crypto_auth_hmacsha256_BYTES);
                    }

                    crypto_auth_hmacsha256_final(ref state, ref temp.DangerousGetPinnableReference());
                    temp.Slice(0, mac.Length).CopyTo(mac);
                }
                finally
                {
                    sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
                }
            }
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

        internal override bool TryVerifyCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(mac.Length <= crypto_auth_hmacsha256_BYTES);

            // crypto_auth_hmacsha256_verify does not support truncated HMACs,
            // so we calculate the MAC ourselves and call sodium_memcmp to
            // compare the expected MAC with the actual MAC.

            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[crypto_auth_hmacsha256_BYTES];
                    temp = new Span<byte>(pointer, crypto_auth_hmacsha256_BYTES);
                }

                crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, keyHandle, (UIntPtr)keyHandle.Length);
                crypto_auth_hmacsha256_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
                crypto_auth_hmacsha256_final(ref state, ref temp.DangerousGetPinnableReference());

                int result = sodium_memcmp(ref temp.DangerousGetPinnableReference(), ref mac.DangerousGetPinnableReference(), (UIntPtr)mac.Length);

                return result == 0;
            }
            finally
            {
                sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
            }
        }

        private static bool SelfTest()
        {
            return (crypto_auth_hmacsha256_bytes() == (UIntPtr)crypto_auth_hmacsha256_BYTES)
                && (crypto_auth_hmacsha256_keybytes() == (UIntPtr)crypto_auth_hmacsha256_KEYBYTES)
                && (crypto_auth_hmacsha256_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha256_state>());
        }
    }
}
