using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  BLAKE2b (keyed)
    //
    //  References:
    //
    //      RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication
    //          Code (MAC)
    //
    //  Parameters:
    //
    //      Key Size - Between 0 and 64 bytes. libsodium recommends a default
    //          size of 32 bytes and a minimum size of 16 bytes.
    //
    //      Input Size - Between 0 and 2^128-1 bytes. (A Span<byte> can only
    //          hold up to 2^31-1 bytes.)
    //
    //      MAC Size - Between 1 and 64 bytes. libsodium recommends a default
    //          size of 32 bytes and a minimum size of 16 bytes.
    //
    public sealed class Blake2bMac : MacAlgorithm
    {
        private static readonly NSecKeyFormatter s_nsecKeyFormatter = new NSecKeyFormatter(crypto_generichash_blake2b_KEYBYTES_MIN, crypto_generichash_blake2b_KEYBYTES_MAX, new byte[]
        {
            0xDE, 0x32, 0x45, 0xDE
        });

        private static readonly Oid s_oid = new Oid(1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 8);

        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter(crypto_generichash_blake2b_KEYBYTES_MIN, crypto_generichash_blake2b_KEYBYTES_MAX);

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Blake2bMac() : base(
            minKeySize: crypto_generichash_blake2b_KEYBYTES_MIN,
            defaultKeySize: crypto_generichash_blake2b_KEYBYTES,
            maxKeySize: crypto_generichash_blake2b_KEYBYTES_MAX,
            minMacSize: crypto_generichash_blake2b_BYTES_MIN,
            defaultMacSize: crypto_generichash_blake2b_BYTES,
            maxMacSize: crypto_generichash_blake2b_BYTES_MAX)
        {
            if (!s_selfTest.Value)
            {
                throw Error.Cryptographic_InitializationFailed();
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(seed.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(seed.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);

            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(seed.Length, out keyHandle);
            keyHandle.Import(seed);
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_generichash_blake2b_KEYBYTES;
        }

        internal override void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(keyHandle.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            crypto_generichash_blake2b_init(out crypto_generichash_blake2b_state state, keyHandle, (UIntPtr)keyHandle.Length, (UIntPtr)mac.Length);
            crypto_generichash_blake2b_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            crypto_generichash_blake2b_final(ref state, ref mac.DangerousGetPinnableReference(), (UIntPtr)mac.Length);
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
            Debug.Assert(keyHandle.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(keyHandle.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[mac.Length];
                    temp = new Span<byte>(pointer, mac.Length);
                }

                crypto_generichash_blake2b_init(out crypto_generichash_blake2b_state state, keyHandle, (UIntPtr)keyHandle.Length, (UIntPtr)temp.Length);
                crypto_generichash_blake2b_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
                crypto_generichash_blake2b_final(ref state, ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);

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
            return (crypto_generichash_blake2b_bytes() == (UIntPtr)crypto_generichash_blake2b_BYTES)
                && (crypto_generichash_blake2b_bytes_max() == (UIntPtr)crypto_generichash_blake2b_BYTES_MAX)
                && (crypto_generichash_blake2b_bytes_min() == (UIntPtr)crypto_generichash_blake2b_BYTES_MIN)
                && (crypto_generichash_blake2b_keybytes() == (UIntPtr)crypto_generichash_blake2b_KEYBYTES)
                && (crypto_generichash_blake2b_keybytes_max() == (UIntPtr)crypto_generichash_blake2b_KEYBYTES_MAX)
                && (crypto_generichash_blake2b_keybytes_min() == (UIntPtr)crypto_generichash_blake2b_KEYBYTES_MIN)
                && (crypto_generichash_blake2b_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_generichash_blake2b_state>());
        }
    }
}
