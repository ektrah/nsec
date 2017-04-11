using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using NSec.Cryptography.Formatting;
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
    public sealed class Blake2b : HashAlgorithm
    {
        private static readonly NSecKeyFormatter s_nsecKeyFormatter = new NSecKeyFormatter(crypto_generichash_blake2b_KEYBYTES_MIN, crypto_generichash_blake2b_KEYBYTES_MAX, new byte[] 
        {
            0xDE, 0x32, 0x45, 0xDE
        });

        private static readonly Oid s_oid = new Oid(1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 8);

        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter(crypto_generichash_blake2b_KEYBYTES_MIN, crypto_generichash_blake2b_KEYBYTES_MAX);

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Blake2b() : base(
            minHashSize: 32,
            defaultHashSize: crypto_generichash_blake2b_BYTES,
            maxHashSize: crypto_generichash_blake2b_BYTES_MAX)
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
            Debug.Assert(seed.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(seed.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);

            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(seed.Length, out keyHandle);
            keyHandle.Import(seed);
        }

        internal override byte[] ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.Export(keyHandle);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.Export(keyHandle);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_generichash_blake2b_KEYBYTES;
        }

        internal override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

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
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        private static void HashCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length >= crypto_generichash_blake2b_KEYBYTES_MIN);
            Debug.Assert(keyHandle.Length <= crypto_generichash_blake2b_KEYBYTES_MAX);
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

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
