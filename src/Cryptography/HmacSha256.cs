using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  HMAC-SHA-256
    //
    //      Hashed Message Authentication Code (HMAC) based on SHA-256
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
    //      Key Size - The key for HMAC-SHA-256 can be of any length. A length
    //          less than L=32 bytes (the output length of SHA-256) is strongly
    //          discouraged. Keys longer than L do not significantly increase
    //          the function strength. Keys longer than B=64 bytes (the block
    //          size of SHA-256) are first hashed using SHA-256.
    //
    //      Nonce - HMAC-SHA-256 does not use nonces.
    //
    //      MAC Size - 32 bytes. The output can be truncated down to 16 bytes
    //          (128 bits of security).
    //
    public sealed class HmacSha256 : MacAlgorithm
    {
        private const int SHA256HashSize = 32; // "L" in RFC 2104
        private const int SHA256MessageBlockSize = 64; // "B" in RFC 2104

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public HmacSha256() : base(
            minKeySize: SHA256HashSize,
            defaultKeySize: SHA256HashSize,
            maxKeySize: SHA256MessageBlockSize,
            minNonceSize: 0,
            maxNonceSize: 0,
            minMacSize: 16,
            defaultMacSize: crypto_auth_hmacsha256_BYTES,
            maxMacSize: crypto_auth_hmacsha256_BYTES)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal override SecureMemoryHandle CreateKey(
            out PublicKey publicKey)
        {
            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(DefaultKeySize);
            randombytes_buf(handle, (IntPtr)handle.Length);
            publicKey = null;
            return handle;
        }

        internal override int GetDerivedKeySize()
        {
            return DefaultKeySize;
        }

        internal override void SignCore(
            SecureMemoryHandle key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(key != null);
            Debug.Assert(nonce.IsEmpty);
            Debug.Assert(mac.Length >= MinMacSize);
            Debug.Assert(mac.Length <= MaxMacSize);

            // crypto_auth_hmacsha256_init accepts a key of arbitrary length,
            // while crypto_auth_hmacsha256 requires a key whose length is
            // exactly crypto_auth_hmacsha256_KEYBYTES. So we use _init here.

            // crypto_auth_hmacsha256_init hashes the key if it is larger than
            // the block size. However, we perform this step already in the
            // TryImportKey method to keep the KeyHandle small, so we never
            // pass a key larger than the block size to _init.

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, key, (IntPtr)key.Length);

            if (!data.IsEmpty)
            {
                crypto_auth_hmacsha256_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            }

            // crypto_auth_hmacsha256_final expects an output buffer with a
            // size of exactly crypto_auth_hmacsha256_BYTES, so we need to
            // copy when truncating the output.

            if (mac.Length == crypto_auth_hmacsha256_BYTES)
            {
                crypto_auth_hmacsha256_final(ref state, ref mac.DangerousGetPinnableReference());
            }
            else
            {
                byte[] result = new byte[crypto_auth_hmacsha256_BYTES]; // TODO: avoid placing sensitive data in managed memory
                crypto_auth_hmacsha256_final(ref state, result);
                new ReadOnlySpan<byte>(result, 0, mac.Length).CopyTo(mac);
            }
        }

        internal override bool TryExportKey(
            Key key,
            KeyBlobFormat format,
            out byte[] result)
        {
            Debug.Assert(key != null);

            if (format != KeyBlobFormat.RawSymmetricKey)
            {
                result = null;
                return false;
            }

            byte[] bytes = new byte[key.Handle.Length];
            key.Handle.Export(bytes);
            result = bytes;
            return true;
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            KeyFlags flags,
            out Key result)
        {
            SecureMemoryHandle handle;

            if (format != KeyBlobFormat.RawSymmetricKey || blob.Length < MinKeySize)
            {
                result = null;
                return false;
            }

            if (blob.Length > SHA256MessageBlockSize)
            {
                handle = SecureMemoryHandle.Alloc(crypto_hash_sha256_BYTES);
                crypto_hash_sha256_init(out crypto_hash_sha256_state state);
                crypto_hash_sha256_update(ref state, ref blob.DangerousGetPinnableReference(), (ulong)blob.Length);
                crypto_hash_sha256_final(ref state, handle);
            }
            else
            {
                handle = SecureMemoryHandle.Alloc(blob.Length);
                handle.Import(blob);
            }

            result = new Key(this, flags, handle, null);
            return true;
        }

        private static bool SelfTest()
        {
            return (crypto_auth_hmacsha256_bytes() == (IntPtr)crypto_auth_hmacsha256_BYTES)
                && (crypto_auth_hmacsha256_keybytes() == (IntPtr)crypto_auth_hmacsha256_KEYBYTES)
                && (crypto_auth_hmacsha256_statebytes() == (IntPtr)Unsafe.SizeOf<crypto_auth_hmacsha256_state>())
                && (crypto_hash_sha256_bytes() == (IntPtr)crypto_hash_sha256_BYTES)
                && (crypto_hash_sha256_statebytes() == (IntPtr)Unsafe.SizeOf<crypto_hash_sha256_state>());
        }
    }
}
