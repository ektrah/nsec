using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
            maxOutputSize: byte.MaxValue * crypto_auth_hmacsha256_BYTES)
        {
            if (!s_selfTest.Value)
            {
                throw Error.Cryptographic_InitializationFailed();
            }
        }

        public int PseudorandomKeySize => crypto_auth_hmacsha256_BYTES;

        public byte[] Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (pseudorandomKey.Length < crypto_auth_hmacsha256_BYTES)
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha256_BYTES.ToString());
            if (count < 0)
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            if (count > MaxOutputSize)
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxOutputSize.ToString());
            if (count == 0)
                return Utilities.Empty<byte>();

            byte[] bytes = new byte[count];
            ExpandCore(pseudorandomKey, info, bytes);
            return bytes;
        }

        public void Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            if (pseudorandomKey.Length < crypto_auth_hmacsha256_BYTES)
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha256_BYTES.ToString());
            if (bytes.Length > MaxOutputSize)
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxOutputSize.ToString());
            if (Utilities.Overlap(bytes, pseudorandomKey))
                throw Error.Argument_OverlapPrk(nameof(bytes));
            if (Utilities.Overlap(bytes, info))
                throw Error.Argument_OverlapInfo(nameof(bytes));
            if (bytes.IsEmpty)
                return;

            ExpandCore(pseudorandomKey, info, bytes);
        }

        public byte[] Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt)
        {
            if (sharedSecret == null)
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));

            byte[] pseudorandomKey = new byte[crypto_auth_hmacsha256_BYTES];
            ExtractCore(sharedSecret.Handle, salt, pseudorandomKey);
            return pseudorandomKey;
        }

        public void Extract(
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

        internal override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha256_BYTES);

            Span<byte> pseudorandomKey;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[crypto_auth_hmacsha256_BYTES];
                    pseudorandomKey = new Span<byte>(pointer, crypto_auth_hmacsha256_BYTES);
                }

                ExtractCore(inputKeyingMaterial, salt, pseudorandomKey);

                ExpandCore(pseudorandomKey, info, bytes);
            }
            finally
            {
                sodium_memzero(ref pseudorandomKey.DangerousGetPinnableReference(), (UIntPtr)pseudorandomKey.Length);
            }
        }

        private static void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(pseudorandomKey.Length >= crypto_auth_hmacsha256_BYTES);
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha256_BYTES);

            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[crypto_auth_hmacsha256_BYTES];
                    temp = new Span<byte>(pointer, crypto_auth_hmacsha256_BYTES);
                }

                int tempLength = 0;
                int offset = 0;
                byte counter = 0;
                int chunkSize;

                while ((chunkSize = bytes.Length - offset) > 0)
                {
                    counter++;

                    crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, ref pseudorandomKey.DangerousGetPinnableReference(), (UIntPtr)pseudorandomKey.Length);
                    crypto_auth_hmacsha256_update(ref state, ref temp.DangerousGetPinnableReference(), (ulong)tempLength);
                    crypto_auth_hmacsha256_update(ref state, ref info.DangerousGetPinnableReference(), (ulong)info.Length);
                    crypto_auth_hmacsha256_update(ref state, ref counter, sizeof(byte));
                    crypto_auth_hmacsha256_final(ref state, ref temp.DangerousGetPinnableReference());

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
                sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
            }
        }

        private static void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha256_BYTES);

            // According to the spec, the salt is set to a string of HashLen
            // zeros if not provided. A ReadOnlySpan<byte> cannot be null, and
            // an empty span seems to yield the same result as a string of
            // HashLen zeros, so we're ignoring this corner case here.

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, ref salt.DangerousGetPinnableReference(), (UIntPtr)salt.Length);
            crypto_auth_hmacsha256_update(ref state, ref inputKeyingMaterial.DangerousGetPinnableReference(), (ulong)inputKeyingMaterial.Length);
            crypto_auth_hmacsha256_final(ref state, ref pseudorandomKey.DangerousGetPinnableReference());
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
