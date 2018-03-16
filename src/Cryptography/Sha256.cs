using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
        private static int s_selfTest;

        public Sha256() : base(
            minHashSize: crypto_hash_sha256_BYTES,
            defaultHashSize: crypto_hash_sha256_BYTES,
            maxHashSize: crypto_hash_sha256_BYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length == crypto_hash_sha256_BYTES);

            crypto_hash_sha256(ref MemoryMarshal.GetReference(hash), in MemoryMarshal.GetReference(data), (ulong)data.Length);
        }

        private protected override bool TryVerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            Debug.Assert(hash.Length <= crypto_hash_sha256_BYTES);

            Span<byte> temp = stackalloc byte[crypto_hash_sha256_BYTES];

            crypto_hash_sha256(ref MemoryMarshal.GetReference(temp), in MemoryMarshal.GetReference(data), (ulong)data.Length);

            int result = sodium_memcmp(in MemoryMarshal.GetReference(temp), in MemoryMarshal.GetReference(hash), (UIntPtr)hash.Length);

            return result == 0;
        }

        private static void SelfTest()
        {
            if ((crypto_hash_sha256_bytes() != (UIntPtr)crypto_hash_sha256_BYTES) ||
                (crypto_hash_sha256_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_hash_sha256_state>()))
            {
                throw Error.Cryptographic_InitializationFailed(8747.ToString("X"));
            }
        }
    }
}
