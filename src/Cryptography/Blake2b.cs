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
    //      Input Size - Between 0 and 2^128-1 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
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

        internal override void FinalizeCore(
            ref IncrementalHashState state,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            int error = crypto_generichash_blake2b_final(
                ref state.blake2b,
                hash,
                (nuint)hash.Length);

            Debug.Assert(error == 0);
        }

        internal override void InitializeCore(
            out IncrementalHashState state)
        {
            Debug.Assert(HashSize >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(HashSize <= crypto_generichash_blake2b_BYTES_MAX);

            int error = crypto_generichash_blake2b_init(
                ref state.blake2b,
                IntPtr.Zero,
                0,
                (nuint)HashSize);

            Debug.Assert(error == 0);
        }

        internal override void UpdateCore(
            ref IncrementalHashState state,
            ReadOnlySpan<byte> data)
        {
            int error = crypto_generichash_blake2b_update(
                ref state.blake2b,
                data,
                (ulong)data.Length);

            Debug.Assert(error == 0);
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            int error = crypto_generichash_blake2b(
                hash,
                (nuint)hash.Length,
                data,
                (ulong)data.Length,
                IntPtr.Zero,
                0);

            Debug.Assert(error == 0);
        }

        private static void SelfTest()
        {
            if ((crypto_generichash_blake2b_bytes() != crypto_generichash_blake2b_BYTES) ||
                (crypto_generichash_blake2b_bytes_max() != crypto_generichash_blake2b_BYTES_MAX) ||
                (crypto_generichash_blake2b_bytes_min() != crypto_generichash_blake2b_BYTES_MIN) ||
                (crypto_generichash_blake2b_statebytes() != (nuint)Unsafe.SizeOf<crypto_generichash_blake2b_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
