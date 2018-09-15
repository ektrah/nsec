using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  SHA-512
    //
    //      FIPS Secure Hash Algorithm (SHA) with a 512-bit message digest
    //
    //  References:
    //
    //      RFC 6234 - US Secure Hash Algorithms (SHA and SHA-based HMAC and
    //          HKDF)
    //
    //  Parameters:
    //
    //      Input Size - Between 0 and 2^125-1 bytes. (A Span<byte> can only
    //          hold up to 2^31-1 bytes.)
    //
    //      Hash Size - 64 bytes (256 bits of security). The output can be
    //          truncated to 32 bytes (128 bits of security). Note that SHA-512
    //          truncated to 32 bytes/256 bits is not the same as SHA-512/256,
    //          which uses a different initial hash value.
    //
    public sealed class Sha512 : HashAlgorithm
    {
        public static readonly int MinHashSize = 32;
        public static readonly int MaxHashSize = crypto_hash_sha512_BYTES;

        private static int s_selfTest;

        public Sha512() : this(
            hashSize: crypto_hash_sha512_BYTES)
        {
        }

        public Sha512(int hashSize) : base(
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

        internal unsafe override bool FinalizeAndVerifyCore(
            ref IncrementalHashState state,
            ReadOnlySpan<byte> hash)
        {
            Debug.Assert(hash.Length <= crypto_hash_sha512_BYTES);

            byte* temp = stackalloc byte[crypto_hash_sha512_BYTES];

            fixed (crypto_hash_sha512_state* state_ = &state.sha512)
            {
                int error = crypto_hash_sha512_final(
                    state_,
                    temp);

                Debug.Assert(error == 0);
            }

            fixed (byte* @out = hash)
            {
                return CryptographicOperations.FixedTimeEquals(temp, @out, hash.Length);
            }
        }

        internal unsafe override void FinalizeCore(
            ref IncrementalHashState state,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length <= crypto_hash_sha512_BYTES);

            byte* temp = stackalloc byte[crypto_hash_sha512_BYTES];

            fixed (crypto_hash_sha512_state* state_ = &state.sha512)
            {
                int error = crypto_hash_sha512_final(
                    state_,
                    temp);

                Debug.Assert(error == 0);
            }

            fixed (byte* @out = hash)
            {
                Unsafe.CopyBlockUnaligned(@out, temp, (uint)hash.Length);
            }
        }

        internal unsafe override void InitializeCore(
            out IncrementalHashState state)
        {
            fixed (crypto_hash_sha512_state* state_ = &state.sha512)
            {
                int error = crypto_hash_sha512_init(
                    state_);

                Debug.Assert(error == 0);
            }
        }

        internal unsafe override void UpdateCore(
            ref IncrementalHashState state,
            ReadOnlySpan<byte> data)
        {
            fixed (crypto_hash_sha512_state* state_ = &state.sha512)
            fixed (byte* @in = data)
            {
                int error = crypto_hash_sha512_update(
                    state_,
                    @in,
                    (ulong)data.Length);

                Debug.Assert(error == 0);
            }
        }

        private protected unsafe override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length <= crypto_hash_sha512_BYTES);

            byte* temp = stackalloc byte[crypto_hash_sha512_BYTES];

            fixed (byte* @in = data)
            {
                int error = crypto_hash_sha512(
                    temp,
                    @in,
                    (ulong)data.Length);

                Debug.Assert(error == 0);
            }

            fixed (byte* @out = hash)
            {
                Unsafe.CopyBlockUnaligned(@out, temp, (uint)hash.Length);
            }
        }

        private protected unsafe override bool VerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            Debug.Assert(hash.Length <= crypto_hash_sha512_BYTES);

            byte* temp = stackalloc byte[crypto_hash_sha512_BYTES];

            fixed (byte* @in = data)
            {
                int error = crypto_hash_sha512(
                    temp,
                    @in,
                    (ulong)data.Length);

                Debug.Assert(error == 0);
            }

            fixed (byte* @out = hash)
            {
                return CryptographicOperations.FixedTimeEquals(temp, @out, hash.Length);
            }
        }

        private static void SelfTest()
        {
            if ((crypto_hash_sha512_bytes() != (UIntPtr)crypto_hash_sha512_BYTES) ||
                (crypto_hash_sha512_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_hash_sha512_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
