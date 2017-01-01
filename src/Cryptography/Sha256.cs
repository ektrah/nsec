using System;
using System.Diagnostics;
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
    //  Parameters:
    //
    //      Hash Size - The output of SHA-256 consists of 32 bytes and can be
    //          truncated. RFC 6920 notes that truncated hashes with a length of
    //          less than 100 bit do not have useful security properties. RFC
    //          2104 recommends for HMAC that the length of the HMAC output
    //          should not be less than half the length of the hash size and
    //          not less than 80 bits. We choose 16 bytes (128 bits) as the
    //          minimum size.
    //
    public sealed class Sha256 : HashAlgorithm
    {
        public Sha256() : base(
            minHashSize: crypto_hash_sha256_BYTES / 2,
            defaultHashSize: crypto_hash_sha256_BYTES,
            maxHashSize: crypto_hash_sha256_BYTES)
        {
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_hash_sha256_BYTES / 2);
            Debug.Assert(hash.Length <= crypto_hash_sha256_BYTES);

            crypto_hash_sha256_init(out crypto_hash_sha256_state state);

            if (!data.IsEmpty)
            {
                crypto_hash_sha256_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            }

            // crypto_hash_sha256_final expects an output buffer with a
            // size of exactly crypto_hash_sha256_BYTES, so we need to
            // copy when truncating the output.

            if (hash.Length == crypto_hash_sha256_BYTES)
            {
                crypto_hash_sha256_final(ref state, ref hash.DangerousGetPinnableReference());
            }
            else
            {
                byte[] result = new byte[crypto_hash_sha256_BYTES]; // TODO: avoid placing sensitive data in managed memory
                crypto_hash_sha256_final(ref state, result);
                new ReadOnlySpan<byte>(result, 0, hash.Length).CopyTo(hash);
            }
        }
    }
}
