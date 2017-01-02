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
    //          discouraged. Keys longer than L do not significantly increase
    //          the function strength. Keys longer than B=128 bytes (the block
    //          size of SHA-512) are first hashed using SHA-512.
    //
    //          libsodium uses crypto_auth_hmacsha512_KEYBYTES=32 by default,
    //          which is less than L.
    //
    //      Nonce - HMAC-SHA-512 does not use nonces.
    //
    //      MAC Size - The output of HMAC-SHA-512 consists of L bytes. The
    //          output can be truncated. The output length should not be less
    //          than half the length of the hash output and not less than 80
    //          bits.
    //
    public sealed class HmacSha512 : AuthenticationAlgorithm
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
            minMacSize: crypto_auth_hmacsha512_BYTES / 2,
            defaultMacSize: crypto_auth_hmacsha512_BYTES,
            maxMacSize: crypto_auth_hmacsha512_BYTES)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal override SecureMemoryHandle CreateDerivedKey()
        {
            return SecureMemoryHandle.Alloc(DefaultKeySize);
        }

        internal override SecureMemoryHandle CreateKey(
            out PublicKey publicKey)
        {
            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(DefaultKeySize);
            randombytes_buf(handle, (IntPtr)handle.Length);
            publicKey = null;
            return handle;
        }

        internal override void SignCore(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(key != null);
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

            crypto_auth_hmacsha512_init(out crypto_auth_hmacsha512_state state, key.Handle, (IntPtr)key.Handle.Length);

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
                byte[] result = new byte[crypto_auth_hmacsha512_BYTES]; // TODO: avoid placing sensitive data in managed memory
                crypto_auth_hmacsha512_final(ref state, result);
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

            if (blob.Length > SHA512MessageBlockSize)
            {
                handle = SecureMemoryHandle.Alloc(crypto_hash_sha512_BYTES);
                crypto_hash_sha512_init(out crypto_hash_sha512_state state);
                crypto_hash_sha512_update(ref state, ref blob.DangerousGetPinnableReference(), (ulong)blob.Length);
                crypto_hash_sha512_final(ref state, handle);
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
            return (crypto_auth_hmacsha512_bytes() == (IntPtr)crypto_auth_hmacsha512_BYTES)
                && (crypto_auth_hmacsha512_keybytes() == (IntPtr)crypto_auth_hmacsha512_KEYBYTES)
                && (crypto_auth_hmacsha512_statebytes() == (IntPtr)Unsafe.SizeOf<crypto_auth_hmacsha512_state>())
                && (crypto_hash_sha512_bytes() == (IntPtr)crypto_hash_sha512_BYTES)
                && (crypto_hash_sha512_statebytes() == (IntPtr)Unsafe.SizeOf<crypto_hash_sha512_state>());
        }
    }
}
