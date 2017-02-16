using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
    //      Input Size - Between 0 and 2^61-1 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
    //
    //      Hash Size - 32 bytes (128 bits of security).
    //
    public sealed class Sha256 : HashAlgorithm
    {
        private static readonly Oid s_oid = new Oid(2, 16, 840, 1, 101, 3, 4, 2, 1);

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Sha256() : base(
            minHashSize: crypto_hash_sha256_BYTES,
            defaultHashSize: crypto_hash_sha256_BYTES,
            maxHashSize: crypto_hash_sha256_BYTES)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length == crypto_hash_sha256_BYTES);

            crypto_hash_sha256_init(out crypto_hash_sha256_state state);
            crypto_hash_sha256_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            crypto_hash_sha256_final(ref state, ref hash.DangerousGetPinnableReference());
        }

        private static bool SelfTest()
        {
            return (crypto_hash_sha256_bytes() == (UIntPtr)crypto_hash_sha256_BYTES)
                && (crypto_hash_sha256_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_hash_sha256_state>());
        }
    }
}
