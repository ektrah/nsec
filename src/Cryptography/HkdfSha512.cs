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
            {
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha512_BYTES);
            }
            if (count < 0)
            {
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            }
            if (count > MaxCount)
            {
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxCount);
            }

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
            {
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), crypto_auth_hmacsha512_BYTES);
            }
            if (bytes.Length > MaxCount)
            {
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxCount);
            }
            if (bytes.Overlaps(pseudorandomKey))
            {
                throw Error.Argument_OverlapPrk(nameof(bytes));
            }
            if (bytes.Overlaps(info))
            {
                throw Error.Argument_OverlapInfo(nameof(bytes));
            }

            ExpandCore(pseudorandomKey, info, bytes);
        }

        internal /*public*/ byte[] Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt)
        {
            if (sharedSecret == null)
            {
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            }

            byte[] pseudorandomKey = new byte[crypto_auth_hmacsha512_BYTES];
            ExtractCore(sharedSecret.Handle, salt, pseudorandomKey);
            return pseudorandomKey;
        }

        internal /*public*/ void Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            if (sharedSecret == null)
            {
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            }
            if (pseudorandomKey.Length != crypto_auth_hmacsha512_BYTES)
            {
                throw Error.Argument_InvalidPrkLengthExact(nameof(pseudorandomKey), crypto_auth_hmacsha512_BYTES);
            }

            ExtractCore(sharedSecret.Handle, salt, pseudorandomKey);
        }

        private protected override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
#if NET5_0_OR_GREATER
            System.Security.Cryptography.HKDF.DeriveKey(
                System.Security.Cryptography.HashAlgorithmName.SHA512,
                inputKeyingMaterial,
                bytes,
                salt,
                info);
#else
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha512_BYTES);

            Span<byte> pseudorandomKey = stackalloc byte[crypto_auth_hmacsha512_BYTES];
            try
            {
                ExtractCore(inputKeyingMaterial, salt, pseudorandomKey);

                ExpandCore(pseudorandomKey, info, bytes);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(pseudorandomKey);
            }
#endif
        }

        private static unsafe void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
#if NET5_0_OR_GREATER
            System.Security.Cryptography.HKDF.Expand(
                System.Security.Cryptography.HashAlgorithmName.SHA512,
                pseudorandomKey,
                bytes,
                info);
#else
            Debug.Assert(pseudorandomKey.Length >= crypto_auth_hmacsha512_BYTES);
            Debug.Assert(bytes.Length <= byte.MaxValue * crypto_auth_hmacsha512_BYTES);

            byte* temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];

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

                    crypto_auth_hmacsha512_state initialState;
                    crypto_auth_hmacsha512_init(&initialState, key, (nuint)pseudorandomKey.Length);

                    while ((chunkSize = bytes.Length - offset) > 0)
                    {
                        counter++;

                        crypto_auth_hmacsha512_state state = initialState;
                        crypto_auth_hmacsha512_update(&state, temp, (ulong)tempLength);
                        crypto_auth_hmacsha512_update(&state, @in, (ulong)info.Length);
                        crypto_auth_hmacsha512_update(&state, &counter, sizeof(byte));
                        crypto_auth_hmacsha512_final(&state, temp);

                        tempLength = crypto_auth_hmacsha512_BYTES;

                        if (chunkSize > crypto_auth_hmacsha512_BYTES)
                        {
                            chunkSize = crypto_auth_hmacsha512_BYTES;
                        }

                        Unsafe.CopyBlockUnaligned(@out + offset, temp, (uint)chunkSize);
                        offset += chunkSize;
                    }
                }
            }
            finally
            {
                Unsafe.InitBlockUnaligned(temp, 0, crypto_auth_hmacsha512_BYTES);
            }
#endif
        }

        private static unsafe void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
#if NET5_0_OR_GREATER
            System.Security.Cryptography.HKDF.Extract(
                System.Security.Cryptography.HashAlgorithmName.SHA512,
                inputKeyingMaterial,
                salt,
                pseudorandomKey);
#else
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha512_BYTES);

            // According to RFC 5869, the salt must be set to a string of
            // HashLen zeros if not provided. A ReadOnlySpan<byte> cannot be
            // "not provided", so this is not implemented.

            fixed (byte* ikm = inputKeyingMaterial)
            fixed (byte* key = salt)
            fixed (byte* @out = pseudorandomKey)
            {
                crypto_auth_hmacsha512_state state;
                crypto_auth_hmacsha512_init(&state, key, (nuint)salt.Length);
                crypto_auth_hmacsha512_update(&state, ikm, (ulong)inputKeyingMaterial.Length);
                crypto_auth_hmacsha512_final(&state, @out);
            }
#endif
        }

        private static unsafe void ExtractCore(
            SecureMemoryHandle inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
#if NET5_0_OR_GREATER
            bool mustCallRelease = false;
            try
            {
                inputKeyingMaterial.DangerousAddRef(ref mustCallRelease);

                System.Security.Cryptography.HKDF.Extract(
                    System.Security.Cryptography.HashAlgorithmName.SHA512,
                    inputKeyingMaterial.DangerousGetSpan(),
                    salt,
                    pseudorandomKey);
            }
            finally
            {
                if (mustCallRelease)
                {
                    inputKeyingMaterial.DangerousRelease();
                }
            }
#else
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha512_BYTES);

            // According to RFC 5869, the salt must be set to a string of
            // HashLen zeros if not provided. A ReadOnlySpan<byte> cannot be
            // "not provided", so this is not implemented.

            fixed (byte* key = salt)
            fixed (byte* @out = pseudorandomKey)
            {
                crypto_auth_hmacsha512_state state;
                crypto_auth_hmacsha512_init(&state, key, (nuint)salt.Length);
                crypto_auth_hmacsha512_update(&state, inputKeyingMaterial, (ulong)inputKeyingMaterial.Size);
                crypto_auth_hmacsha512_final(&state, @out);
            }
#endif
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha512_bytes() != crypto_auth_hmacsha512_BYTES) ||
                (crypto_auth_hmacsha512_statebytes() != (nuint)Unsafe.SizeOf<crypto_auth_hmacsha512_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
