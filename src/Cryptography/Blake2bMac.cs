using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
    //      Input Size - Between 0 and 2^128-1 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
    //
    //      MAC Size - Between 1 and 64 bytes. libsodium recommends a default
    //          size of 32 bytes and a minimum size of 16 bytes.
    //
    public sealed class Blake2bMac : MacAlgorithm
    {
        public static readonly int MinKeySize = crypto_generichash_blake2b_KEYBYTES_MIN;
        public static readonly int MaxKeySize = crypto_generichash_blake2b_KEYBYTES_MAX;
        public static readonly int MinMacSize = crypto_generichash_blake2b_BYTES_MIN;
        public static readonly int MaxMacSize = crypto_generichash_blake2b_BYTES_MAX;

        private const uint NSecBlobHeader = 0xDE6245DE;

        private static int s_selfTest;

        public Blake2bMac() : this(
            keySize: crypto_generichash_blake2b_KEYBYTES,
            macSize: crypto_generichash_blake2b_BYTES)
        {
        }

        public Blake2bMac(int keySize, int macSize) : base(
            keySize: keySize,
            macSize: macSize)
        {
            if (keySize < MinKeySize || keySize > MaxKeySize)
            {
                throw Error.ArgumentOutOfRange_KeySize(nameof(keySize), keySize, MinKeySize, MaxKeySize);
            }
            if (macSize < MinMacSize || macSize > MaxMacSize)
            {
                throw Error.ArgumentOutOfRange_MacSize(nameof(macSize), macSize, MaxMacSize, MaxMacSize);
            }
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out PublicKey? publicKey)
        {
            Debug.Assert(seed.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(seed.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);

            publicKey = null;
            keyHandle = SecureMemoryHandle.CreateFrom(seed);
        }

        internal unsafe override bool FinalizeAndVerifyCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> temp = stackalloc byte[mac.Length];

            fixed (crypto_generichash_blake2b_state* state_ = &state.blake2b)
            fixed (byte* @out = temp)
            {
                int error = crypto_generichash_blake2b_final(
                    state_,
                    @out,
                    (nuint)temp.Length);

                Debug.Assert(error == 0);
            }

            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(temp, mac);
        }

        internal unsafe override void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac)
        {
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            fixed (crypto_generichash_blake2b_state* state_ = &state.blake2b)
            fixed (byte* @out = mac)
            {
                int error = crypto_generichash_blake2b_final(
                    state_,
                    @out,
                    (nuint)mac.Length);

                Debug.Assert(error == 0);
            }
        }

        internal override int GetSeedSize()
        {
            return KeySize;
        }

        internal unsafe override void InitializeCore(
            SecureMemoryHandle keyHandle,
            out IncrementalMacState state)
        {
            Debug.Assert(keyHandle.Size >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(keyHandle.Size <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(MacSize >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(MacSize <= crypto_generichash_blake2b_BYTES_MAX);

            fixed (crypto_generichash_blake2b_state* state_ = &state.blake2b)
            {
                int error = crypto_generichash_blake2b_init(
                    state_,
                    keyHandle,
                    (nuint)keyHandle.Size,
                    (nuint)MacSize);

                Debug.Assert(error == 0);
            }
        }

        internal override bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            return format switch
            {
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryExport(keyHandle, blob, out blobSize),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryExport(NSecBlobHeader, KeySize, MacSize, keyHandle, blob, out blobSize),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle? keyHandle,
            out PublicKey? publicKey)
        {
            publicKey = null;

            return format switch
            {
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(KeySize, blob, out keyHandle),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, MacSize, blob, out keyHandle),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal unsafe override void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data)
        {
            fixed (crypto_generichash_blake2b_state* state_ = &state.blake2b)
            fixed (byte* @in = data)
            {
                int error = crypto_generichash_blake2b_update(
                    state_,
                    @in,
                    (ulong)data.Length);

                Debug.Assert(error == 0);
            }
        }

        private protected unsafe override void MacCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle.Size >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(keyHandle.Size <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            fixed (byte* @out = mac)
            fixed (byte* @in = data)
            {
                int error = crypto_generichash_blake2b(
                    @out,
                    (nuint)mac.Length,
                    @in,
                    (ulong)data.Length,
                    keyHandle,
                    (nuint)keyHandle.Size);

                Debug.Assert(error == 0);
            }
        }

        private protected unsafe override bool VerifyCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(keyHandle.Size >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(keyHandle.Size <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> temp = stackalloc byte[mac.Length];

            fixed (byte* @out = temp)
            fixed (byte* @in = data)
            {
                int error = crypto_generichash_blake2b(
                    @out,
                    (nuint)temp.Length,
                    @in,
                    (ulong)data.Length,
                    keyHandle,
                    (nuint)keyHandle.Size);

                Debug.Assert(error == 0);
            }

            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(temp, mac);
        }

        private static void SelfTest()
        {
            if ((crypto_generichash_blake2b_bytes() != crypto_generichash_blake2b_BYTES) ||
                (crypto_generichash_blake2b_bytes_max() != crypto_generichash_blake2b_BYTES_MAX) ||
                (crypto_generichash_blake2b_bytes_min() != crypto_generichash_blake2b_BYTES_MIN) ||
                (crypto_generichash_blake2b_keybytes() != crypto_generichash_blake2b_KEYBYTES) ||
                (crypto_generichash_blake2b_keybytes_max() != crypto_generichash_blake2b_KEYBYTES_MAX) ||
                (crypto_generichash_blake2b_keybytes_min() != crypto_generichash_blake2b_KEYBYTES_MIN) ||
                (crypto_generichash_blake2b_statebytes() != (nuint)Unsafe.SizeOf<crypto_generichash_blake2b_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
