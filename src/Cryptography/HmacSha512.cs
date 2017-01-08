using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  HMAC-SHA-512
    //
    //      Hashed Message Authentication Code (HMAC) based on SHA-512
    //
    //  References:
    //
    //      RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
    //
    //      RFC 6234 - US Secure Hash Algorithms (SHA and SHA-based HMAC and
    //          HKDF)
    //
    //  Parameters:
    //
    //      Key Size - The key for HMAC-SHA-512 can be of any length. A length
    //          less than L=64 bytes (the output length of SHA-512) is strongly
    //          discouraged. (libsodium recommends a default size of
    //          crypto_auth_hmacsha512_KEYBYTES=32 bytes.) Keys longer than L do
    //          not significantly increase the function strength. Keys longer
    //          than B=128 bytes (the block size of SHA-512) are first hashed
    //          using SHA-512.
    //
    //      Nonce - HMAC-SHA-512 does not use nonces.
    //
    //      MAC Size - 64 bytes. The output can be truncated down to 16 bytes
    //          (128 bits of security). To match the security of SHA-512, the
    //          output length should not be less than half of L (i.e., not less
    //          than 32 bytes).
    //
    public sealed class HmacSha512 : MacAlgorithm
    {
        private const int SHA512HashSize = 64; // "L" in RFC 2104
        private const int SHA512MessageBlockSize = 128; // "B" in RFC 2104

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public HmacSha512() : base(
            minKeySize: SHA512HashSize,
            defaultKeySize: SHA512HashSize,
            maxKeySize: SHA512MessageBlockSize,
            minNonceSize: 0,
            maxNonceSize: 0,
            minMacSize: 16,
            defaultMacSize: crypto_auth_hmacsha512_BYTES,
            maxMacSize: crypto_auth_hmacsha512_BYTES)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal override void CreateKey(
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(DefaultKeySize, out keyHandle);
            randombytes_buf(keyHandle, (UIntPtr)keyHandle.Length);
        }

        internal override int GetDerivedKeySize()
        {
            return DefaultKeySize;
        }

        internal override void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(nonce.IsEmpty);
            Debug.Assert(mac.Length >= MinMacSize);
            Debug.Assert(mac.Length <= MaxMacSize);

            // crypto_auth_hmacsha512_init accepts a key of arbitrary length,
            // while crypto_auth_hmacsha512 requires a key whose length is
            // exactly crypto_auth_hmacsha512_KEYBYTES. So we use _init here.

            // crypto_auth_hmacsha512_init hashes the key if it is larger than
            // the block size. However, we perform this step already in the
            // TryImportKey method to keep the KeyHandle small, so we never
            // pass a key larger than the block size to _init.

            crypto_auth_hmacsha512_init(out crypto_auth_hmacsha512_state state, keyHandle, (UIntPtr)keyHandle.Length);

            if (!data.IsEmpty)
            {
                crypto_auth_hmacsha512_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            }

            // crypto_auth_hmacsha512_final expects an output buffer with a
            // size of exactly crypto_auth_hmacsha512_BYTES, so we need to
            // copy when truncating the output.

            if (mac.Length == crypto_auth_hmacsha512_BYTES)
            {
                crypto_auth_hmacsha512_final(ref state, ref mac.DangerousGetPinnableReference());
            }
            else
            {
                Span<byte> temp = new byte[crypto_auth_hmacsha512_BYTES]; // TODO: avoid placing sensitive data in managed memory
                crypto_auth_hmacsha512_final(ref state, ref temp.DangerousGetPinnableReference());
                temp.Slice(0, mac.Length).CopyTo(mac);
            }
        }

        internal override bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            out byte[] result)
        {
            Debug.Assert(keyHandle != null);

            if (format != KeyBlobFormat.RawSymmetricKey)
            {
                result = null;
                return false;
            }

            result = new byte[keyHandle.Length];
            keyHandle.Export(result);
            return true;
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            if (format != KeyBlobFormat.RawSymmetricKey || blob.Length < MinKeySize)
            {
                keyHandle = null;
                publicKeyBytes = null;
                return false;
            }

            if (blob.Length > SHA512MessageBlockSize)
            {
                publicKeyBytes = null;
                SecureMemoryHandle.Alloc(crypto_hash_sha512_BYTES, out keyHandle);
                crypto_hash_sha512_init(out crypto_hash_sha512_state state);
                crypto_hash_sha512_update(ref state, ref blob.DangerousGetPinnableReference(), (ulong)blob.Length);
                crypto_hash_sha512_final(ref state, keyHandle);
            }
            else
            {
                publicKeyBytes = null;
                SecureMemoryHandle.Alloc(blob.Length, out keyHandle);
                keyHandle.Import(blob);
            }

            return true;
        }

        private static bool SelfTest()
        {
            return (crypto_auth_hmacsha512_bytes() == (UIntPtr)crypto_auth_hmacsha512_BYTES)
                && (crypto_auth_hmacsha512_keybytes() == (UIntPtr)crypto_auth_hmacsha512_KEYBYTES)
                && (crypto_auth_hmacsha512_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha512_state>())
                && (crypto_hash_sha512_bytes() == (UIntPtr)crypto_hash_sha512_BYTES)
                && (crypto_hash_sha512_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_hash_sha512_state>());
        }
    }
}
