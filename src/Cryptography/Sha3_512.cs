using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  SHA3-512
    //
    //  References:
    //
    //      FIPS PUB 202 - SHA-3 Standard: Permutation-Based Hash and
    //          Extendable-Output Functions
    //
    //  Parameters:
    //
    //      Input Size - Any. (A Span<byte> can hold only up to 2^31-1 bytes.)
    //
    //      Hash Size - 64 bytes (256 bits of security).
    //
    public sealed class Sha3_512 : HashAlgorithm
    {
        public static readonly int MinHashSize = crypto_hash_sha3512_BYTES;
        public static readonly int MaxHashSize = crypto_hash_sha3512_BYTES;

        private static int s_selfTest;

        public Sha3_512() : this(
            hashSize: crypto_hash_sha3512_BYTES)
        {
        }

        public Sha3_512(int hashSize) : base(
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
            Debug.Assert(hash.Length <= crypto_hash_sha3512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_hash_sha3512_BYTES];

            int error = crypto_hash_sha3512_final(
                ref state.sha3_512,
                temp);

            Debug.Assert(error == 0);

            temp[..hash.Length].CopyTo(hash);
        }

        internal override void InitializeCore(
            out IncrementalHashState state)
        {
            int error = crypto_hash_sha3512_init(
                ref state.sha3_512);

            Debug.Assert(error == 0);
        }

        internal override void UpdateCore(
            ref IncrementalHashState state,
            ReadOnlySpan<byte> data)
        {
            int error = crypto_hash_sha3512_update(
                ref state.sha3_512,
                data,
                (ulong)data.Length);

            Debug.Assert(error == 0);
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length <= crypto_hash_sha3512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_hash_sha3512_BYTES];

            int error = crypto_hash_sha3512(
                temp,
                data,
                (ulong)data.Length);

            Debug.Assert(error == 0);

            temp[..hash.Length].CopyTo(hash);
        }

        private static void SelfTest()
        {
            if ((crypto_hash_sha3512_bytes() != crypto_hash_sha3512_BYTES) ||
                (crypto_hash_sha3512_statebytes() != (nuint)Unsafe.SizeOf<crypto_hash_sha3512_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
