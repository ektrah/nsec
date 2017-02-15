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
    //      Input Size - Between 0 and 2^128-1 bytes. Since a Span<byte> can
    //          hold between 0 to 2^31-1 bytes, we do not check the length of
    //          inputs.
    //
    //      Hash Size - Between 1 and 64 bytes. For 128 bits of security, the
    //          output length should not be less than 32 bytes (BLAKE2b-256).
    //
    public sealed class Blake2 : HashAlgorithm
    {
        private const int BLAKE2B_KEYBYTES = 64;
        private const int BLAKE2B_OUTBYTES = 64;

        private static readonly Oid s_oid = new Oid(1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 8);

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        private static readonly KeyBlobFormat[] s_supportedKeyBlobFormats =
        {
            KeyBlobFormat.RawSymmetricKey,
        };

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
            HashCore(key.Handle, data, hash);
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
            HashCore(key.Handle, data, hash);
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

            HashCore(key.Handle, data, hash);
        }

        internal override void CreateKey(
            SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            publicKeyBytes = null;
        }

        internal override int ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob)
        {
            if (format != KeyBlobFormat.RawSymmetricKey)
                throw new FormatException();
            if (blob.Length < keyHandle.Length)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(blob));

            Debug.Assert(keyHandle != null);
            return keyHandle.Export(blob);
        }

        internal override int GetDefaultKeySize()
        {
            return DefaultKeySize;
        }

        internal override int GetKeyBlobSize(KeyBlobFormat format)
        {
            if (format != KeyBlobFormat.RawSymmetricKey)
                throw new FormatException();

            return MaxKeySize;
        }

        internal override ReadOnlySpan<KeyBlobFormat> GetSupportedKeyBlobFormats()
        {
            return s_supportedKeyBlobFormats;
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length > 0);
            Debug.Assert(hash.Length <= BLAKE2B_OUTBYTES);

            crypto_generichash_blake2b_init(out crypto_generichash_blake2b_state state, IntPtr.Zero, UIntPtr.Zero, (UIntPtr)hash.Length);
            crypto_generichash_blake2b_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            crypto_generichash_blake2b_final(ref state, ref hash.DangerousGetPinnableReference(), (UIntPtr)hash.Length);
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            if (format != KeyBlobFormat.RawSymmetricKey || blob.Length < MinKeySize || blob.Length > MaxKeySize)
            {
                keyHandle = null;
                publicKeyBytes = null;
                return false;
            }

            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(blob.Length, out keyHandle);
            keyHandle.Import(blob);
            return true;
        }

        private static void HashCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length >= 0);
            Debug.Assert(keyHandle.Length <= BLAKE2B_KEYBYTES);
            Debug.Assert(hash.Length > 0);
            Debug.Assert(hash.Length <= BLAKE2B_OUTBYTES);

            crypto_generichash_blake2b_init(out crypto_generichash_blake2b_state state, keyHandle, (UIntPtr)keyHandle.Length, (UIntPtr)hash.Length);
            crypto_generichash_blake2b_update(ref state, ref data.DangerousGetPinnableReference(), (ulong)data.Length);
            crypto_generichash_blake2b_final(ref state, ref hash.DangerousGetPinnableReference(), (UIntPtr)hash.Length);
        }

        private static bool SelfTest()
        {
            return (crypto_generichash_blake2b_bytes() == (UIntPtr)crypto_generichash_blake2b_BYTES)
                && (crypto_generichash_blake2b_bytes_max() == (UIntPtr)crypto_generichash_blake2b_BYTES_MAX)
                && (crypto_generichash_blake2b_bytes_min() == (UIntPtr)crypto_generichash_blake2b_BYTES_MIN)
                && (crypto_generichash_blake2b_keybytes() == (UIntPtr)crypto_generichash_blake2b_KEYBYTES)
                && (crypto_generichash_blake2b_keybytes_max() == (UIntPtr)crypto_generichash_blake2b_KEYBYTES_MAX)
                && (crypto_generichash_blake2b_keybytes_min() == (UIntPtr)crypto_generichash_blake2b_KEYBYTES_MIN)
                && (crypto_generichash_blake2b_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_generichash_blake2b_state>());
        }
    }
}
