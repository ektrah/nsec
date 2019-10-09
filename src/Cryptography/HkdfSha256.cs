using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  HKDF-SHA-256
    //
    //      HMAC-based Key Derivation Function (HKDF) using HMAC-SHA-256
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
    //      Pseudorandom Key Size - The first stage of HKDF-SHA-256 takes the
    //          input keying material and extracts from it a pseudorandom key
    //          of HashLen=32 bytes. The second stage expands a pseudorandom
    //          key of _at least_ HashLen bytes to the desired length.
    //
    //      Salt Size - HKDF is defined to operate with and without random salt.
    //          Ideally, the salt value is a random string of the length
    //          HashLen.
    //
    //      Shared Info Size - Any.
    //
    //      Output Size - The length of the output key material must be less
    //          than or equal to 255*HashLen=8160 bytes.
    //
    public sealed class HkdfSha256 : KeyDerivationAlgorithm
    {
        private static int s_selfTest;

        public HkdfSha256() : base(
            supportsSalt: true,
            maxCount: byte.MaxValue * crypto_auth_hmacsha256_BYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal /*public*/ int PseudorandomKeySize => crypto_auth_hmacsha256_BYTES;

        internal /*public*/ byte[] Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (pseudorandomKey.Length < crypto_auth_hmacsha256_BYTES)
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha256_BYTES);
            if (count < 0)
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            if (count > MaxCount)
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxCount);

            byte[] bytes = new byte[count];
            ExpandCore(pseudorandomKey, info, bytes);
            return bytes;
        }

        internal /*public*/ void Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            if (pseudorandomKey.Length < crypto_auth_hmacsha256_BYTES)
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha256_BYTES);
            if (bytes.Length > MaxCount)
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxCount);
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

            byte[] pseudorandomKey = new byte[crypto_auth_hmacsha256_BYTES];
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
            if (pseudorandomKey.Length != crypto_auth_hmacsha256_BYTES)
                throw Error.Argument_InvalidPrkLengthExact(nameof(pseudorandomKey), crypto_auth_hmacsha256_BYTES);

            ExtractCore(sharedSecret.Span, salt, pseudorandomKey);
        }

        private protected override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha256_BYTES);

            Span<byte> pseudorandomKey = stackalloc byte[crypto_auth_hmacsha256_BYTES];
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

        private static unsafe void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(pseudorandomKey.Length >= crypto_auth_hmacsha256_BYTES);
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha256_BYTES);

            byte* temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];

            try
            {
                fixed (byte* key = pseudorandomKey)
                fixed (byte* @in = info)
                fixed (byte* @out = bytes)
                {
                    int tempLength = 0;
                    int offset = 0;
                    byte counter = 0;
                    int chunkSize;

                    while ((chunkSize = bytes.Length - offset) > 0)
                    {
                        counter++;

                        crypto_auth_hmacsha256_state state;
                        crypto_auth_hmacsha256_init(&state, key, (UIntPtr)pseudorandomKey.Length);
                        crypto_auth_hmacsha256_update(&state, temp, (ulong)tempLength);
                        crypto_auth_hmacsha256_update(&state, @in, (ulong)info.Length);
                        crypto_auth_hmacsha256_update(&state, &counter, sizeof(byte));
                        crypto_auth_hmacsha256_final(&state, temp);

                        tempLength = crypto_auth_hmacsha256_BYTES;

                        if (chunkSize > crypto_auth_hmacsha256_BYTES)
                        {
                            chunkSize = crypto_auth_hmacsha256_BYTES;
                        }

                        Unsafe.CopyBlockUnaligned(@out + offset, temp, (uint)chunkSize);
                        offset += chunkSize;
                    }
                }
            }
            finally
            {
                Unsafe.InitBlockUnaligned(temp, 0, crypto_auth_hmacsha256_BYTES);
            }
        }

        private static unsafe void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha256_BYTES);

            // According to RFC 5869, the salt must be set to a string of
            // HashLen zeros if not provided. A ReadOnlySpan<byte> cannot be
            // "not provided", so this is not implemented.

            fixed (byte* key = salt)
            fixed (byte* @in = inputKeyingMaterial)
            fixed (byte* @out = pseudorandomKey)
            {
                crypto_auth_hmacsha256_state state;
                crypto_auth_hmacsha256_init(&state, key, (UIntPtr)salt.Length);
                crypto_auth_hmacsha256_update(&state, @in, (ulong)inputKeyingMaterial.Length);
                crypto_auth_hmacsha256_final(&state, @out);
            }
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha256_bytes() != (UIntPtr)crypto_auth_hmacsha256_BYTES) ||
                (crypto_auth_hmacsha256_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha256_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
