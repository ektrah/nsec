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
    public sealed class HkdfSha256 : KeyDerivationAlgorithm2
    {
        private static int s_selfTest;

        public HkdfSha256() : base(
            supportsSalt: true,
            maxCount: byte.MaxValue * crypto_auth_hmacsha256_BYTES,
            pseudorandomKeySize: crypto_auth_hmacsha256_BYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

#if NET5_0_OR_GREATER
        private protected override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            System.Security.Cryptography.HKDF.DeriveKey(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                inputKeyingMaterial,
                bytes,
                salt,
                info);
        }

        private protected override void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            System.Security.Cryptography.HKDF.Expand(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                pseudorandomKey,
                bytes,
                info);
        }

        private protected override void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            System.Security.Cryptography.HKDF.Extract(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                inputKeyingMaterial,
                salt,
                pseudorandomKey);
        }
#else
        private protected override unsafe void ExpandCore(
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

                    crypto_auth_hmacsha256_state initialState;
                    crypto_auth_hmacsha256_init(&initialState, key, (nuint)pseudorandomKey.Length);

                    while ((chunkSize = bytes.Length - offset) > 0)
                    {
                        counter++;

                        crypto_auth_hmacsha256_state state = initialState;
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

        private protected override unsafe void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha256_BYTES);

            // According to RFC 5869, the salt must be set to a string of
            // HashLen zeros if not provided. A ReadOnlySpan<byte> cannot be
            // "not provided", so this is not implemented.

            fixed (byte* ikm = inputKeyingMaterial)
            fixed (byte* key = salt)
            fixed (byte* @out = pseudorandomKey)
            {
                crypto_auth_hmacsha256_state state;
                crypto_auth_hmacsha256_init(&state, key, (nuint)salt.Length);
                crypto_auth_hmacsha256_update(&state, ikm, (ulong)inputKeyingMaterial.Length);
                crypto_auth_hmacsha256_final(&state, @out);
            }
        }

        private protected override unsafe void ExtractCore(
            SecureMemoryHandle sharedSecretHandle,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha256_BYTES);

            // According to RFC 5869, the salt must be set to a string of
            // HashLen zeros if not provided. A ReadOnlySpan<byte> cannot be
            // "not provided", so this is not implemented.

            fixed (byte* key = salt)
            fixed (byte* @out = pseudorandomKey)
            {
                crypto_auth_hmacsha256_state state;
                crypto_auth_hmacsha256_init(&state, key, (nuint)salt.Length);
                crypto_auth_hmacsha256_update(&state, sharedSecretHandle, (ulong)sharedSecretHandle.Size);
                crypto_auth_hmacsha256_final(&state, @out);
            }
        }
#endif

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha256_bytes() != crypto_auth_hmacsha256_BYTES) ||
                (crypto_auth_hmacsha256_statebytes() != (nuint)Unsafe.SizeOf<crypto_auth_hmacsha256_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
