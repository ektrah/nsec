using System;
using System.Diagnostics;
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
    //      Hash Size - The output of SHA-512 consists of 64 bytes and can be
    //          truncated. RFC 6920 notes that truncated hashes with a length of
    //          less than 100 bit do not have useful security properties. RFC
    //          2104 recommends for HMAC that the length of the HMAC output
    //          should not be less than half the length of the hash size and
    //          not less than 80 bits. We choose 32 bytes (256 bits) as the
    //          minimum size.
    //
    public sealed class Sha512 : HashAlgorithm
    {
        public Sha512() : base(
            minHashSize: crypto_hash_sha512_BYTES / 2,
            defaultHashSize: crypto_hash_sha512_BYTES,
            maxHashSize: crypto_hash_sha512_BYTES)
        {
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_hash_sha512_BYTES / 2);
            Debug.Assert(hash.Length <= crypto_hash_sha512_BYTES);

            crypto_hash_sha512_init(out crypto_hash_sha512_state state);

            if (!data.IsEmpty)
            {
                crypto_hash_sha512_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            }

            // crypto_hash_sha512_final expects an output buffer with a
            // size of exactly crypto_hash_sha512_BYTES, so we need to
            // copy when truncating the output.

            if (hash.Length == crypto_hash_sha512_BYTES)
            {
                crypto_hash_sha512_final(ref state, ref hash.DangerousGetPinnableReference());
            }
            else
            {
                byte[] result = new byte[crypto_hash_sha512_BYTES]; // TODO: avoid placing sensitive data in managed memory
                crypto_hash_sha512_final(ref state, result);
                new ReadOnlySpan<byte>(result, 0, hash.Length).CopyTo(hash);
            }
        }
    }
}
