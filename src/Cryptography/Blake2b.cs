using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    // RFC 7693
    public sealed class Blake2b : HashAlgorithm
    {
        public Blake2b() : base(
            minHashSize: crypto_generichash_blake2b_BYTES_MIN,
            defaultHashSize: crypto_generichash_blake2b_BYTES,
            maxHashSize: crypto_generichash_blake2b_BYTES_MAX)
        {
        }

        public int DefaultKeySize => crypto_generichash_blake2b_KEYBYTES;

        public int MaxKeySize => crypto_generichash_blake2b_KEYBYTES_MAX;

        public int MinKeySize => crypto_generichash_blake2b_KEYBYTES_MIN;

        public byte[] Hash(
            Key key,
            ReadOnlySpan<byte> data)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));

            byte[] hash = new byte[crypto_generichash_blake2b_BYTES];
            HashCore(key, data, hash);
            return hash;
        }

        public byte[] Hash(
            Key key,
            ReadOnlySpan<byte> data,
            int hashSize)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (hashSize < crypto_generichash_blake2b_BYTES_MIN)
                throw new ArgumentOutOfRangeException(nameof(hashSize));
            if (hashSize > crypto_generichash_blake2b_BYTES_MAX)
                throw new ArgumentOutOfRangeException(nameof(hashSize));

            byte[] hash = new byte[hashSize];
            HashCore(key, data, hash);
            return hash;
        }

        public void Hash(
            Key key,
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (hash.Length < crypto_generichash_blake2b_BYTES_MIN)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(hash));
            if (hash.Length > crypto_generichash_blake2b_BYTES_MAX)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(hash));

            HashCore(key, data, hash);
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

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            crypto_generichash_blake2b_init(out crypto_generichash_blake2b_state state, IntPtr.Zero, IntPtr.Zero, (IntPtr)hash.Length);
            crypto_generichash_blake2b_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            crypto_generichash_blake2b_final(ref state, ref hash.DangerousGetPinnableReference(), (IntPtr)hash.Length);
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
            if (format != KeyBlobFormat.RawSymmetricKey || blob.Length < MinKeySize || blob.Length > MaxKeySize)
            {
                result = null;
                return false;
            }

            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(blob.Length);
            handle.Import(blob);
            result = new Key(this, flags, handle, null);
            return true;
        }

        private static void HashCore(
            Key key,
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.Handle.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(key.Handle.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            crypto_generichash_blake2b_init(out crypto_generichash_blake2b_state state, key.Handle, (IntPtr)key.Handle.Length, (IntPtr)hash.Length);
            crypto_generichash_blake2b_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            crypto_generichash_blake2b_final(ref state, ref hash.DangerousGetPinnableReference(), (IntPtr)hash.Length);
        }
    }
}
