using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  BLAKE2b
    //
    //  References:
    //
    //      RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication
    //          Code (MAC)
    //
    //  Parameters:
    //
    //      Key Size - Between 0 and 64 bytes. libsodium recommends a default
    //          size of 32 bytes and a minimum size of 16 bytes.
    //
    //      Hash Size - Between 1 and 64 bytes. For 128 bits of security, the
    //          output length should not be less than 32 bytes (blake2b256).
    //
    //      Input Size - Between 0 and 2^128-1 bytes. Since a Span<byte> can
    //          hold between 0 to 2^31-1 bytes, we do not check the length of
    //          inputs.
    //
    public sealed class Blake2 : HashAlgorithm
    {
        private const int BLAKE2B_KEYBYTES = 64;
        private const int BLAKE2B_OUTBYTES = 64;

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Blake2() : base(
            minHashSize: 32,
            defaultHashSize: 32,
            maxHashSize: BLAKE2B_OUTBYTES)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
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

            byte[] hash = new byte[DefaultHashSize];
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
            if (hashSize < MinHashSize)
                throw new ArgumentOutOfRangeException(nameof(hashSize));
            if (hashSize > MaxHashSize)
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
            if (hash.Length < MinHashSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(hash));
            if (hash.Length > MaxHashSize)
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
            Debug.Assert(hash.Length > 0);
            Debug.Assert(hash.Length <= BLAKE2B_OUTBYTES);

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
            Debug.Assert(key.Handle.Length >= 0);
            Debug.Assert(key.Handle.Length <= BLAKE2B_KEYBYTES);
            Debug.Assert(hash.Length > 0);
            Debug.Assert(hash.Length <= BLAKE2B_OUTBYTES);

            crypto_generichash_blake2b_init(out crypto_generichash_blake2b_state state, key.Handle, (IntPtr)key.Handle.Length, (IntPtr)hash.Length);
            crypto_generichash_blake2b_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            crypto_generichash_blake2b_final(ref state, ref hash.DangerousGetPinnableReference(), (IntPtr)hash.Length);
        }

        private static bool SelfTest()
        {
            return (crypto_generichash_blake2b_bytes() == (IntPtr)crypto_generichash_blake2b_BYTES)
                && (crypto_generichash_blake2b_bytes_max() == (IntPtr)crypto_generichash_blake2b_BYTES_MAX)
                && (crypto_generichash_blake2b_bytes_min() == (IntPtr)crypto_generichash_blake2b_BYTES_MIN)
                && (crypto_generichash_blake2b_keybytes() == (IntPtr)crypto_generichash_blake2b_BYTES)
                && (crypto_generichash_blake2b_keybytes_max() == (IntPtr)crypto_generichash_blake2b_BYTES_MAX)
                && (crypto_generichash_blake2b_keybytes_min() == (IntPtr)crypto_generichash_blake2b_BYTES_MIN)
                && (crypto_generichash_blake2b_statebytes() == (IntPtr)Unsafe.SizeOf<crypto_generichash_blake2b_state>());
        }
    }
}
