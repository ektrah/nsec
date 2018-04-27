using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  SHA-256
    //
    //      FIPS Secure Hash Algorithm (SHA) with a 256-bit message digest
    //
    //  References:
    //
    //      RFC 6234 - US Secure Hash Algorithms (SHA and SHA-based HMAC and
    //          HKDF)
    //
    //      RFC 5754 - Using SHA2 Algorithms with Cryptographic Message Syntax
    //
    //  Parameters:
    //
    //      Input Size - Between 0 and 2^61-1 bytes. (A Span<byte> can only
    //          hold up to 2^31-1 bytes.)
    //
    //      Hash Size - 32 bytes (128 bits of security).
    //
    public sealed class Sha256 : HashAlgorithm
    {
        public static readonly int MinHashSize = crypto_hash_sha256_BYTES;
        public static readonly int MaxHashSize = crypto_hash_sha256_BYTES;

        private static int s_selfTest;

        public Sha256() : this(
            hashSize: crypto_hash_sha256_BYTES)
        {
        }

        public Sha256(int hashSize) : base(
            hashSize: hashSize)
        {
            if (hashSize < MinHashSize || hashSize > MaxHashSize)
            {
                throw Error.ArgumentOutOfRange_HashSize(nameof(hashSize), hashSize.ToString(), MinHashSize.ToString(), MaxHashSize.ToString());
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
            Debug.Assert(hash.Length == crypto_hash_sha256_BYTES);

            Span<byte> temp = stackalloc byte[crypto_hash_sha256_BYTES];

            crypto_hash_sha256_final(ref state.sha256, ref temp.GetPinnableReference());

            return CryptographicOperations.FixedTimeEquals(temp, hash);
        }

        internal override void FinalizeCore(
            ref IncrementalHashState state,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length == crypto_hash_sha256_BYTES);

            crypto_hash_sha256_final(ref state.sha256, ref hash.GetPinnableReference());
        }

        internal override void InitializeCore(
            int hashSize,
            out IncrementalHashState state)
        {
            Debug.Assert(hashSize == crypto_hash_sha256_BYTES);

            crypto_hash_sha256_init(out state.sha256);
        }

        internal override void UpdateCore(
            ref IncrementalHashState state,
            ReadOnlySpan<byte> data)
        {
            crypto_hash_sha256_update(ref state.sha256, in data.GetPinnableReference(), (ulong)data.Length);
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length == crypto_hash_sha256_BYTES);

            crypto_hash_sha256(ref hash.GetPinnableReference(), in data.GetPinnableReference(), (ulong)data.Length);
        }

        private protected override bool VerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            Debug.Assert(hash.Length == crypto_hash_sha256_BYTES);

            Span<byte> temp = stackalloc byte[crypto_hash_sha256_BYTES];

            crypto_hash_sha256(ref temp.GetPinnableReference(), in data.GetPinnableReference(), (ulong)data.Length);

            return CryptographicOperations.FixedTimeEquals(temp, hash);
        }

        private static void SelfTest()
        {
            if ((crypto_hash_sha256_bytes() != (UIntPtr)crypto_hash_sha256_BYTES) ||
                (crypto_hash_sha256_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_hash_sha256_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
