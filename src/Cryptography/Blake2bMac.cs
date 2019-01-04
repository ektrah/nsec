using System;
using System.Buffers;
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
    //      Input Size - Between 0 and 2^128-1 bytes. (A Span<byte> can only
    //          hold up to 2^31-1 bytes.)
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
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            Debug.Assert(seed.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(seed.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);

            publicKey = null;
            owner = memoryPool.Rent(seed.Length);
            memory = owner.Memory.Slice(0, seed.Length);
            seed.CopyTo(owner.Memory.Span);
        }

        internal unsafe override bool FinalizeAndVerifyCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            byte* buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            crypto_generichash_blake2b_state* state_ = Align64(buffer);
            *state_ = state.blake2b;

            byte* temp = stackalloc byte[mac.Length];

            int error = crypto_generichash_blake2b_final(
                state_,
                temp,
                (UIntPtr)mac.Length);

            Debug.Assert(error == 0);

            state.blake2b = *state_;

            fixed (byte* @out = mac)
            {
                return CryptographicOperations.FixedTimeEquals(temp, @out, mac.Length);
            }
        }

        internal unsafe override void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac)
        {
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            byte* buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            crypto_generichash_blake2b_state* state_ = Align64(buffer);
            *state_ = state.blake2b;

            fixed (byte* @out = mac)
            {
                int error = crypto_generichash_blake2b_final(
                    state_,
                    @out,
                    (UIntPtr)mac.Length);

                Debug.Assert(error == 0);
            }

            state.blake2b = *state_;
        }

        internal override int GetSeedSize()
        {
            return KeySize;
        }

        internal unsafe override void InitializeCore(
            ReadOnlySpan<byte> key,
            out IncrementalMacState state)
        {
            Debug.Assert(key.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(key.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(MacSize >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(MacSize <= crypto_generichash_blake2b_BYTES_MAX);

            byte* buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            crypto_generichash_blake2b_state* state_ = Align64(buffer);

            fixed (byte* k = key)
            {
                int error = crypto_generichash_blake2b_init(
                    state_,
                    k,
                    (UIntPtr)key.Length,
                    (UIntPtr)MacSize);

                Debug.Assert(error == 0);
            }

            state.blake2b = *state_;
        }

        internal override bool TryExportKey(
            ReadOnlySpan<byte> key,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return RawKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.NSecSymmetricKey:
                return NSecKeyFormatter.TryExport(NSecBlobHeader, KeySize, MacSize, key, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            publicKey = null;

            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return RawKeyFormatter.TryImport(KeySize, blob, memoryPool, out memory, out owner);
            case KeyBlobFormat.NSecSymmetricKey:
                return NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, MacSize, blob, memoryPool, out memory, out owner);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal unsafe override void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data)
        {
            byte* buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            crypto_generichash_blake2b_state* state_ = Align64(buffer);
            *state_ = state.blake2b;

            fixed (byte* @in = data)
            {
                int error = crypto_generichash_blake2b_update(
                    state_,
                    @in,
                    (ulong)data.Length);

                Debug.Assert(error == 0);
            }

            state.blake2b = *state_;
        }

        private protected unsafe override void MacCore(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(key.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(key.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            fixed (byte* @out = mac)
            fixed (byte* @in = data)
            fixed (byte* k = key)
            {
                int error = crypto_generichash_blake2b(
                    @out,
                    (UIntPtr)mac.Length,
                    @in,
                    (ulong)data.Length,
                    k,
                    (UIntPtr)key.Length);

                Debug.Assert(error == 0);
            }
        }

        private protected unsafe override bool VerifyCore(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(key.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(key.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(mac.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(mac.Length <= crypto_generichash_blake2b_BYTES_MAX);

            byte* temp = stackalloc byte[mac.Length];

            fixed (byte* @in = data)
            fixed (byte* k = key)
            {
                int error = crypto_generichash_blake2b(
                    temp,
                    (UIntPtr)mac.Length,
                    @in,
                    (ulong)data.Length,
                    k,
                    (UIntPtr)key.Length);

                Debug.Assert(error == 0);
            }

            fixed (byte* @out = mac)
            {
                return CryptographicOperations.FixedTimeEquals(temp, @out, mac.Length);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe crypto_generichash_blake2b_state* Align64(byte* value)
        {
            unchecked
            {
                return sizeof(byte*) == sizeof(uint)
                    ? (crypto_generichash_blake2b_state*)(((uint)value + 63u) & ~63u)
                    : (crypto_generichash_blake2b_state*)(((ulong)value + 63ul) & ~63ul);
            }
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
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
