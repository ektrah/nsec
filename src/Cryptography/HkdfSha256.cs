using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  HKDF-SHA-256
    //
    //      HMAC-based Key Derivation Function (HKDF) based on HMAC-SHA-256
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
    //      Output Size - The length of the output key material must be less
    //          than or equal to 255*HashLen=8160 bytes.
    //
    //      Uses Salt - HKDF-SHA-256 supports salt.
    //
    public sealed class HkdfSha256 : KeyDerivationAlgorithm
    {
        public HkdfSha256() : base(
            usesSalt: true)
        {
        }

        public int MaxOutputSize => 255 * crypto_auth_hmacsha256_BYTES;

        public int PseudorandomKeySize => crypto_auth_hmacsha256_BYTES;

        public byte[] Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (pseudorandomKey.Length < crypto_auth_hmacsha256_BYTES)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(pseudorandomKey));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count > MaxOutputSize)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count == 0)
                return new byte[0];

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
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(pseudorandomKey));
            if (bytes.Length > MaxOutputSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(bytes));
            if (bytes.IsEmpty)
                return;

            ExpandCore(pseudorandomKey, info, bytes);
        }

        public byte[] Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt)
        {
            if (sharedSecret == null)
                throw new ArgumentNullException(nameof(sharedSecret));

            byte[] pseudorandomKey = new byte[crypto_auth_hmacsha256_BYTES];
            ExtractCore(sharedSecret, salt, pseudorandomKey);
            return pseudorandomKey;
        }

        public void Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            if (sharedSecret == null)
                throw new ArgumentNullException(nameof(sharedSecret));
            if (pseudorandomKey.Length != crypto_auth_hmacsha256_BYTES)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(pseudorandomKey));

            ExtractCore(sharedSecret, salt, pseudorandomKey);
        }

        internal override void DeriveBytesCore(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            if (bytes.Length > MaxOutputSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(bytes));

            Debug.Assert(sharedSecret != null);

            byte[] pseudorandomKey = new byte[crypto_auth_hmacsha256_BYTES]; // TODO: avoid placing sensitive data in managed memory
            ExtractCore(sharedSecret, salt, pseudorandomKey);
            ExpandCore(pseudorandomKey, info, bytes);
        }

        internal override void DeriveKeyCore(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            SecureMemoryHandle key)
        {
            Debug.Assert(sharedSecret != null);
            Debug.Assert(key != null);
            Debug.Assert(key.Length <= MaxOutputSize);

            bool addedRef = false;
            try
            {
                key.DangerousAddRef(ref addedRef);

                byte[] pseudorandomKey = new byte[crypto_auth_hmacsha256_BYTES]; // TODO: avoid placing sensitive data in managed memory
                ExtractCore(sharedSecret, salt, pseudorandomKey);
                ExpandCore(pseudorandomKey, info, key.DangerousGetSpan());
            }
            finally
            {
                if (addedRef)
                {
                    key.DangerousRelease();
                }
            }
        }

        private static void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(pseudorandomKey.Length >= crypto_auth_hmacsha256_BYTES);
            Debug.Assert(bytes.Length <= 255 * crypto_auth_hmacsha256_BYTES);

            byte[] t = new byte[crypto_auth_hmacsha256_BYTES]; // TODO: avoid placing sensitive data in managed memory
            int tLen = 0;
            int offset = 0;
            byte counter = 0;
            int chunkSize;

            while ((chunkSize = bytes.Length - offset) > 0)
            {
                counter++;

                crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, ref pseudorandomKey.DangerousGetPinnableReference(), (IntPtr)pseudorandomKey.Length);
                crypto_auth_hmacsha256_update(ref state, t, (ulong)tLen);
                crypto_auth_hmacsha256_update(ref state, ref info.DangerousGetPinnableReference(), (ulong)info.Length);
                crypto_auth_hmacsha256_update(ref state, ref counter, sizeof(byte));
                crypto_auth_hmacsha256_final(ref state, t);

                tLen = crypto_auth_hmacsha256_BYTES;

                if (chunkSize > crypto_auth_hmacsha256_BYTES)
                    chunkSize = crypto_auth_hmacsha256_BYTES;
                new ReadOnlySpan<byte>(t, 0, chunkSize).CopyTo(bytes.Slice(offset));
                offset += chunkSize;
            }
        }

        private static void ExtractCore(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            Debug.Assert(sharedSecret != null);
            Debug.Assert(pseudorandomKey.Length == crypto_auth_hmacsha256_BYTES);

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, ref salt.DangerousGetPinnableReference(), (IntPtr)salt.Length);
            crypto_auth_hmacsha256_update(ref state, sharedSecret.Handle, (ulong)sharedSecret.Handle.Length);
            crypto_auth_hmacsha256_final(ref state, ref pseudorandomKey.DangerousGetPinnableReference());
        }
    }
}
