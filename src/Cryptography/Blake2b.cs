using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  BLAKE2b (unkeyed)
    //
    //  References:
    //
    //      RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication
    //          Code (MAC)
    //
    //  Parameters:
    //
    //      Input Size - Between 0 and 2^128-1 bytes. (A Span<byte> can only
    //          hold up to 2^31-1 bytes.)
    //
    //      Hash Size - Between 1 and 64 bytes. For 128 bits of security, the
    //          output length should not be less than 32 bytes (BLAKE2b-256).
    //
    public sealed class Blake2b : HashAlgorithm
    {
        public static readonly int MinHashSize = 32;
        public static readonly int MaxHashSize = crypto_generichash_blake2b_BYTES_MAX;

        private static int s_selfTest;

        public Blake2b() : this(
            hashSize: crypto_generichash_blake2b_BYTES)
        {
        }

        public Blake2b(int hashSize) : base(
            hashSize: hashSize)
        {
            if (hashSize < MinHashSize || hashSize > MaxHashSize)
            {
                throw Error.ArgumentOutOfRange_HashSize(nameof(hashSize), hashSize, MinHashSize, MaxHashSize);
            }
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal override bool FinalizeAndVerifyCore(
            ref IncrementalHashState state,
            ReadOnlySpan<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            ref crypto_generichash_blake2b_state state_ = ref AlignPinnedReference(ref buffer.GetPinnableReference());

            Span<byte> temp = stackalloc byte[hash.Length];

            state_ = state.blake2b;

            int error = crypto_generichash_blake2b_final(
                ref state_,
                ref temp.GetPinnableReference(),
                (UIntPtr)temp.Length);

            Debug.Assert(error == 0);

            return CryptographicOperations.FixedTimeEquals(temp, hash);
        }

        internal override void FinalizeCore(
            ref IncrementalHashState state,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            ref crypto_generichash_blake2b_state state_ = ref AlignPinnedReference(ref buffer.GetPinnableReference());

            state_ = state.blake2b;

            int error = crypto_generichash_blake2b_final(
                ref state_,
                ref hash.GetPinnableReference(),
                (UIntPtr)hash.Length);

            Debug.Assert(error == 0);

            state.blake2b = state_;
        }

        internal override void InitializeCore(
            int hashSize,
            out IncrementalHashState state)
        {
            Debug.Assert(hashSize >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hashSize <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            ref crypto_generichash_blake2b_state aligned_ = ref AlignPinnedReference(ref buffer.GetPinnableReference());

            int error = crypto_generichash_blake2b_init(
                out aligned_,
                IntPtr.Zero,
                UIntPtr.Zero,
                (UIntPtr)hashSize);

            Debug.Assert(error == 0);

            state.blake2b = aligned_;
        }

        internal override void UpdateCore(
            ref IncrementalHashState state,
            ReadOnlySpan<byte> data)
        {
            Span<byte> buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            ref crypto_generichash_blake2b_state state_ = ref AlignPinnedReference(ref buffer.GetPinnableReference());

            state_ = state.blake2b;

            int error = crypto_generichash_blake2b_update(
                ref state_,
                in data.GetPinnableReference(),
                (ulong)data.Length);

            Debug.Assert(error == 0);

            state.blake2b = state_;
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            int error = crypto_generichash_blake2b(
                ref hash.GetPinnableReference(),
                (UIntPtr)hash.Length,
                in data.GetPinnableReference(),
                (ulong)data.Length,
                IntPtr.Zero,
                UIntPtr.Zero);

            Debug.Assert(error == 0);
        }

        private protected override bool VerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> temp = stackalloc byte[hash.Length];

            int error = crypto_generichash_blake2b(
                ref temp.GetPinnableReference(),
                (UIntPtr)temp.Length,
                in data.GetPinnableReference(),
                (ulong)data.Length,
                IntPtr.Zero,
                UIntPtr.Zero);

            Debug.Assert(error == 0);

            return CryptographicOperations.FixedTimeEquals(temp, hash);
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
                (crypto_generichash_blake2b_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_generichash_blake2b_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
