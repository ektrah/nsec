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
    //      Input Size - Between 0 and 2^128-1 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
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

        public Blake2() : base(
            minHashSize: 32,
            defaultHashSize: 32,
            maxHashSize: BLAKE2B_OUTBYTES)
        {
            if (!s_selfTest.Value)
                throw Error.Cryptographic_InitializationFailed();
        }

        public int DefaultKeySize => crypto_generichash_blake2b_KEYBYTES;

        public int MaxKeySize => crypto_generichash_blake2b_KEYBYTES_MAX;

        public int MinKeySize => crypto_generichash_blake2b_KEYBYTES_MIN;

        public byte[] Hash(
            Key key,
            ReadOnlySpan<byte> data)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);

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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (hashSize < MinHashSize || hashSize > MaxHashSize)
                throw Error.ArgumentOutOfRange_HashSize(nameof(hashSize), hashSize.ToString(), MinHashSize.ToString(), MaxHashSize.ToString());

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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (hash.Length < MinHashSize || hash.Length > MaxHashSize)
                throw Error.Argument_HashSize(nameof(hash), hash.Length.ToString(), MinHashSize.ToString(), MaxHashSize.ToString());

            HashCore(key.Handle, data, hash);
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(seed.Length, out keyHandle);
            keyHandle.Import(seed);
        }

        internal override byte[] ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format)
        {
            if (format != KeyBlobFormat.RawSymmetricKey)
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());

            Debug.Assert(keyHandle != null);

            byte[] blob = new byte[keyHandle.Length];
            keyHandle.Export(blob);
            return blob;
        }

        internal override int GetDefaultSeedSize()
        {
            return DefaultKeySize;
        }

        internal override int GetKeyBlobSize(
            KeyBlobFormat format)
        {
            if (format != KeyBlobFormat.RawSymmetricKey)
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());

            return MaxKeySize;
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
            if (format != KeyBlobFormat.RawSymmetricKey)
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());

            if (blob.Length < MinKeySize || blob.Length > MaxKeySize)
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
