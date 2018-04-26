using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  HKDF-SHA-512
    //
    //      HMAC-based Key Derivation Function (HKDF) using HMAC-SHA-512
    //
    //  References:
    //
    //      RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function
    //          (HKDF)
    //
    //      RFC 6234 - US Secure Hash Algorithms (SHA and SHA-based HMAC and
    //          HKDF)
    //
    //  Parameters
    //
    //      Pseudorandom Key Size - The first stage of HKDF-SHA-512 takes the
    //          input keying material and extracts from it a pseudorandom key
    //          of HashLen=64 bytes. The second stage expands a pseudorandom
    //          key of _at least_ HashLen bytes to the desired length.
    //
    //      Salt Size - HKDF is defined to operate with and without random salt.
    //          Ideally, the salt value is a random string of the length
    //          HashLen.
    //
    //      Shared Info Size - Any.
    //
    //      Output Size - The length of the output key material must be less
    //          than or equal to 255*HashLen=16320 bytes.
    //
    public sealed class HkdfSha512 : KeyDerivationAlgorithm
    {
        private static int s_selfTest;

        public HkdfSha512() : base(
            supportsSalt: true,
            maxCount: byte.MaxValue * crypto_auth_hmacsha512_BYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal /*public*/ int PseudorandomKeySize => crypto_auth_hmacsha512_BYTES;

        internal /*public*/ byte[] Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (pseudorandomKey.Length < crypto_auth_hmacsha512_BYTES)
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha512_BYTES.ToString());
            if (count < 0)
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            if (count > MaxCount)
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxCount.ToString());

            byte[] bytes = new byte[count];
            ExpandCore(pseudorandomKey, info, bytes);
            return bytes;
        }

        internal /*public*/ void Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            if (pseudorandomKey.Length < crypto_auth_hmacsha512_BYTES)
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha512_BYTES.ToString());
            if (bytes.Length > MaxCount)
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxCount.ToString());
            if (bytes.Overlaps(pseudorandomKey))
                throw Error.Argument_OverlapPrk(nameof(bytes));
            if (bytes.Overlaps(info))
                throw Error.Argument_OverlapInfo(nameof(bytes));

            ExpandCore(pseudorandomKey, info, bytes);
        }

        internal /*public*/ byte[] Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt)
        {
            if (sharedSecret == null)
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));

            byte[] pseudorandomKey = new byte[crypto_auth_hmacsha512_BYTES];
            ExtractCore(sharedSecret.Span, salt, pseudorandomKey);
            return pseudorandomKey;
        }

        internal /*public*/ void Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            if (sharedSecret == null)
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            if (pseudorandomKey.Length != crypto_auth_hmacsha512_BYTES)
                throw Error.Argument_InvalidPrkLengthExact(nameof(pseudorandomKey), crypto_auth_hmacsha512_BYTES.ToString());

            ExtractCore(sharedSecret.Span, salt, pseudorandomKey);
        }

        private protected override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha512_BYTES);

            Span<byte> pseudorandomKey = stackalloc byte[crypto_auth_hmacsha512_BYTES];
            try
            {
                ExtractCore(inputKeyingMaterial, salt, pseudorandomKey);

                ExpandCore(pseudorandomKey, info, bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pseudorandomKey);
            }
        }

        private static void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(pseudorandomKey.Length >= crypto_auth_hmacsha512_BYTES);
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];
            try
            {
                int tempLength = 0;
                int offset = 0;
                byte counter = 0;
                int chunkSize;

                while ((chunkSize = bytes.Length - offset) > 0)
                {
                    counter++;

                    crypto_auth_hmacsha512_init(out crypto_auth_hmacsha512_state state, in pseudorandomKey.GetPinnableReference(), (UIntPtr)pseudorandomKey.Length);
                    crypto_auth_hmacsha512_update(ref state, in temp.GetPinnableReference(), (ulong)tempLength);
                    crypto_auth_hmacsha512_update(ref state, in info.GetPinnableReference(), (ulong)info.Length);
                    crypto_auth_hmacsha512_update(ref state, in counter, sizeof(byte));
                    crypto_auth_hmacsha512_final(ref state, ref temp.GetPinnableReference());

                    tempLength = crypto_auth_hmacsha512_BYTES;

                    if (chunkSize > crypto_auth_hmacsha512_BYTES)
                    {
                        chunkSize = crypto_auth_hmacsha512_BYTES;
                    }

                    temp.Slice(0, chunkSize).CopyTo(bytes.Slice(offset));
                    offset += chunkSize;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(temp);
            }
        }

        private static void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha512_BYTES);

            // According to RFC 5869, the salt must be set to a string of
            // HashLen zeros if not provided. A ReadOnlySpan<byte> cannot be
            // "not provided" and an empty span seems to yield the same result
            // as a string of HashLen zeros, so the corner case is ignored here.

            crypto_auth_hmacsha512_init(out crypto_auth_hmacsha512_state state, in salt.GetPinnableReference(), (UIntPtr)salt.Length);
            crypto_auth_hmacsha512_update(ref state, in inputKeyingMaterial.GetPinnableReference(), (ulong)inputKeyingMaterial.Length);
            crypto_auth_hmacsha512_final(ref state, ref pseudorandomKey.GetPinnableReference());
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha512_bytes() != (UIntPtr)crypto_auth_hmacsha512_BYTES) ||
                (crypto_auth_hmacsha512_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha512_state>()))
            {
                throw Error.Cryptographic_InitializationFailed();
            }
        }
    }
}
