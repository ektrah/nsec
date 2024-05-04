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
    //      Input Size - Between 0 and 2^125-1 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
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

        internal override void FinalizeCore(
            ref IncrementalHashState state,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length <= crypto_hash_sha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_hash_sha512_BYTES];

            int error = crypto_hash_sha512_final(
                ref state.sha512,
                temp);

            Debug.Assert(error == 0);

            temp[..hash.Length].CopyTo(hash);
        }

        internal override void InitializeCore(
            out IncrementalHashState state)
        {
            int error = crypto_hash_sha512_init(
                ref state.sha512);

            Debug.Assert(error == 0);
        }

        internal override void UpdateCore(
            ref IncrementalHashState state,
            ReadOnlySpan<byte> data)
        {
            int error = crypto_hash_sha512_update(
                ref state.sha512,
                data,
                (ulong)data.Length);

            Debug.Assert(error == 0);
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length <= crypto_hash_sha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_hash_sha512_BYTES];

            int error = crypto_hash_sha512(
                temp,
                data,
                (ulong)data.Length);

            Debug.Assert(error == 0);

            temp[..hash.Length].CopyTo(hash);
        }

        private static void SelfTest()
        {
            if ((crypto_hash_sha512_bytes() != crypto_hash_sha512_BYTES) ||
                (crypto_hash_sha512_statebytes() != (nuint)Unsafe.SizeOf<crypto_hash_sha512_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
