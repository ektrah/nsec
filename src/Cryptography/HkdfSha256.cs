using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public HkdfSha256() : base(
            supportsSalt: true,
            maxCount: byte.MaxValue * crypto_auth_hmacsha256_BYTES)
        {
            if (!s_selfTest.Value)
            {
                throw Error.Cryptographic_InitializationFailed(9127.ToString("X"));
            }
        }

        internal /*public*/ int PseudorandomKeySize => crypto_auth_hmacsha256_BYTES;

        internal /*public*/ byte[] Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (pseudorandomKey.Length < crypto_auth_hmacsha256_BYTES)
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha256_BYTES.ToString());
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
            if (pseudorandomKey.Length < crypto_auth_hmacsha256_BYTES)
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha256_BYTES.ToString());
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

            byte[] pseudorandomKey = new byte[crypto_auth_hmacsha256_BYTES];
            ExtractCore(sharedSecret.Handle, salt, pseudorandomKey);
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
                throw Error.Argument_InvalidPrkLengthExact(nameof(pseudorandomKey), crypto_auth_hmacsha256_BYTES.ToString());

            ExtractCore(sharedSecret.Handle, salt, pseudorandomKey);
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
                sodium_memzero(ref MemoryMarshal.GetReference(pseudorandomKey), (UIntPtr)pseudorandomKey.Length);
            }
        }

        private static void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(pseudorandomKey.Length >= crypto_auth_hmacsha256_BYTES);
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha256_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];
            try
            {
                int tempLength = 0;
                int offset = 0;
                byte counter = 0;
                int chunkSize;

                while ((chunkSize = bytes.Length - offset) > 0)
                {
                    counter++;

                    crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, in MemoryMarshal.GetReference(pseudorandomKey), (UIntPtr)pseudorandomKey.Length);
                    crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(temp), (ulong)tempLength);
                    crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(info), (ulong)info.Length);
                    crypto_auth_hmacsha256_update(ref state, in counter, sizeof(byte));
                    crypto_auth_hmacsha256_final(ref state, ref MemoryMarshal.GetReference(temp));

                    tempLength = crypto_auth_hmacsha256_BYTES;

                    if (chunkSize > crypto_auth_hmacsha256_BYTES)
                    {
                        chunkSize = crypto_auth_hmacsha256_BYTES;
                    }

                    temp.Slice(0, chunkSize).CopyTo(bytes.Slice(offset));
                    offset += chunkSize;
                }
            }
            finally
            {
                sodium_memzero(ref MemoryMarshal.GetReference(temp), (UIntPtr)temp.Length);
            }
        }

        private static void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha256_BYTES);

            // According to RFC 5869, the salt must be set to a string of
            // HashLen zeros if not provided. A ReadOnlySpan<byte> cannot be
            // "not provided" and an empty span seems to yield the same result
            // as a string of HashLen zeros, so the corner case is ignored here.

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, in MemoryMarshal.GetReference(salt), (UIntPtr)salt.Length);
            crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(inputKeyingMaterial), (ulong)inputKeyingMaterial.Length);
            crypto_auth_hmacsha256_final(ref state, ref MemoryMarshal.GetReference(pseudorandomKey));
        }

        private static void ExtractCore(
            SecureMemoryHandle inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            bool addedRef = false;
            try
            {
                inputKeyingMaterial.DangerousAddRef(ref addedRef);

                ExtractCore(inputKeyingMaterial.DangerousGetSpan(), salt, pseudorandomKey);
            }
            finally
            {
                if (addedRef)
                {
                    inputKeyingMaterial.DangerousRelease();
                }
            }
        }

        private static bool SelfTest()
        {
            return (crypto_auth_hmacsha256_bytes() == (UIntPtr)crypto_auth_hmacsha256_BYTES)
                && (crypto_auth_hmacsha256_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha256_state>());
        }
    }
}
