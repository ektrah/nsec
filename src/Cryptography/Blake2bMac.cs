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
        private static readonly NSecKeyFormatter s_nsecKeyFormatter = new NSecKeyFormatter(crypto_generichash_blake2b_KEYBYTES_MIN, crypto_generichash_blake2b_KEYBYTES_MAX, new byte[] { 0xDE, 0x32, 0x45, 0xDE });

        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter(crypto_generichash_blake2b_KEYBYTES_MIN, crypto_generichash_blake2b_KEYBYTES_MAX);

        private static int s_selfTest;

        public Blake2bMac() : base(
            minKeySize: crypto_generichash_blake2b_KEYBYTES_MIN,
            defaultKeySize: crypto_generichash_blake2b_KEYBYTES,
            maxKeySize: crypto_generichash_blake2b_KEYBYTES_MAX,
            minMacSize: crypto_generichash_blake2b_BYTES_MIN,
            defaultMacSize: crypto_generichash_blake2b_BYTES,
            maxMacSize: crypto_generichash_blake2b_BYTES_MAX)
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
            Debug.Assert(seed.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(seed.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);

            publicKeyBytes = null;
            SecureMemoryHandle.Import(seed, out keyHandle);
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_generichash_blake2b_KEYBYTES;
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
            Debug.Assert(keyHandle.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(keyHandle.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            crypto_generichash_blake2b(ref MemoryMarshal.GetReference(mac), (UIntPtr)mac.Length, in MemoryMarshal.GetReference(data), (ulong)data.Length, keyHandle, (UIntPtr)keyHandle.Length);
        }

        private protected override bool TryVerifyCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(keyHandle.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> temp = stackalloc byte[mac.Length];

            crypto_generichash_blake2b(ref MemoryMarshal.GetReference(temp), (UIntPtr)temp.Length, in MemoryMarshal.GetReference(data), (ulong)data.Length, keyHandle, (UIntPtr)keyHandle.Length);

            int result = sodium_memcmp(in MemoryMarshal.GetReference(temp), in MemoryMarshal.GetReference(mac), (UIntPtr)mac.Length);

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe ref crypto_generichash_blake2b_state AlignPinnedReference(ref byte value)
        {
            return ref sizeof(byte*) == sizeof(uint)
                ? ref Unsafe.AsRef<crypto_generichash_blake2b_state>((void*)(((uint)Unsafe.AsPointer(ref value) + 63u) & ~63u))
                : ref Unsafe.AsRef<crypto_generichash_blake2b_state>((void*)(((ulong)Unsafe.AsPointer(ref value) + 63ul) & ~63ul));
        }

        private static void SelfTest()
        {
            if ((crypto_generichash_blake2b_bytes() != (UIntPtr)crypto_generichash_blake2b_BYTES) ||
                (crypto_generichash_blake2b_bytes_max() != (UIntPtr)crypto_generichash_blake2b_BYTES_MAX) ||
                (crypto_generichash_blake2b_bytes_min() != (UIntPtr)crypto_generichash_blake2b_BYTES_MIN) ||
                (crypto_generichash_blake2b_keybytes() != (UIntPtr)crypto_generichash_blake2b_KEYBYTES) ||
                (crypto_generichash_blake2b_keybytes_max() != (UIntPtr)crypto_generichash_blake2b_KEYBYTES_MAX) ||
                (crypto_generichash_blake2b_keybytes_min() != (UIntPtr)crypto_generichash_blake2b_KEYBYTES_MIN) ||
                (crypto_generichash_blake2b_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_generichash_blake2b_state>()))
            {
                throw Error.Cryptographic_InitializationFailed(9391.ToString("X"));
            }
        }
    }
}
