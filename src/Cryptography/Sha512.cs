using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
    //      Input Size - Between 0 and 2^125-1 bytes. Since a Span<byte> can
    //          hold between 0 to 2^31-1 bytes, we do not check the length of
    //          inputs.
    //
    //      Hash Size - 64 bytes (256 bits of security). The output can be
    //          truncated down to 32 bytes (SHA-512/256) (128 bits of security).
    //
    public sealed class Sha512 : HashAlgorithm
    {
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Sha512() : base(
            minHashSize: crypto_hash_sha512_BYTES / 2,
            defaultHashSize: crypto_hash_sha512_BYTES,
            maxHashSize: crypto_hash_sha512_BYTES)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
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
                Span<byte> temp;
                try
                {
                    unsafe
                    {
                        byte* pointer = stackalloc byte[crypto_hash_sha512_BYTES];
                        temp = new Span<byte>(pointer, crypto_hash_sha512_BYTES);
                    }

                    crypto_hash_sha512_final(ref state, ref temp.DangerousGetPinnableReference());
                    temp.Slice(0, hash.Length).CopyTo(hash);
                }
                finally
                {
                    sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
                }
            }
        }

        private static bool SelfTest()
        {
            return (crypto_hash_sha512_bytes() == (UIntPtr)crypto_hash_sha512_BYTES)
                && (crypto_hash_sha512_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_hash_sha512_state>());
        }
    }
}
