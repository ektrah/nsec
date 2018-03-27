using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using NSec.Cryptography.Formatting;
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
    //      RFC 4231 - Identifiers and Test Vectors for HMAC-SHA-224,
    //          HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
    //
    //  Parameters:
    //
    //      Key Size - The key for HMAC-SHA-512 can be of any length. A length
    //          less than L=64 bytes (the output length of SHA-512) is strongly
    //          discouraged. (libsodium recommends a default size of
    //          crypto_auth_hmacsha512_KEYBYTES=32 bytes.) Keys longer than L do
    //          not significantly increase the function strength.
    //
    //      MAC Size - 64 bytes. The output can be truncated to 16 bytes
    //          (128 bits of security). To match the security of SHA-512, the
    //          output length should not be less than half of L (i.e., not less
    //          than 32 bytes).
    //
    public sealed class HmacSha512 : MacAlgorithm
    {
        public static readonly int MinKeySize = crypto_hash_sha512_BYTES;
        public static readonly int MaxKeySize = crypto_hash_sha512_BYTES;
        public static readonly int MinMacSize = crypto_auth_hmacsha512_BYTES;
        public static readonly int MaxMacSize = crypto_auth_hmacsha512_BYTES;

        private static readonly NSecKeyFormatter s_nsecKeyFormatter = new NSecKeyFormatter(0xDE3347DE);

        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter();

        private static int s_selfTest;

        public HmacSha512() : this(
            keySize: crypto_hash_sha512_BYTES,
            macSize: crypto_auth_hmacsha512_BYTES)
        {
        }

        public HmacSha512(int keySize, int macSize) : base(
            keySize: keySize,
            macSize: macSize)
        {
            if (keySize < MinKeySize || keySize > MaxKeySize)
            {
                throw Error.ArgumentOutOfRange_KeySize(nameof(keySize), keySize.ToString(), MinKeySize.ToString(), MaxKeySize.ToString());
            }
            if (macSize < MinMacSize || macSize > MaxMacSize)
            {
                throw Error.ArgumentOutOfRange_MacSize(nameof(macSize), macSize.ToString(), MaxMacSize.ToString(), MaxMacSize.ToString());
            }
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out PublicKey publicKey)
        {
            publicKey = null;
            SecureMemoryHandle.Import(seed, out keyHandle);
        }

        internal override bool FinalizeAndTryVerifyCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(mac.Length == crypto_auth_hmacsha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];

            crypto_auth_hmacsha512_final(ref state.hmacsha512, ref MemoryMarshal.GetReference(temp));

            return CryptographicOperations.FixedTimeEquals(temp, mac);
        }

        internal override void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac)
        {
            Debug.Assert(mac.Length == crypto_auth_hmacsha512_BYTES);

            crypto_auth_hmacsha512_final(ref state.hmacsha512, ref MemoryMarshal.GetReference(mac));
        }

        internal override int GetDefaultSeedSize()
        {
            return KeySize;
        }

        internal override void InitializeCore(
            SecureMemoryHandle keyHandle,
            int macSize,
            out IncrementalMacState state)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(macSize == crypto_auth_hmacsha512_BYTES);

            crypto_auth_hmacsha512_init(out state.hmacsha512, keyHandle, (UIntPtr)keyHandle.Length);
        }

        internal override bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out PublicKey publicKey)
        {
            publicKey = null;

            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryImport(KeySize, blob, out keyHandle);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryImport(KeySize, blob, out keyHandle);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data)
        {
            crypto_auth_hmacsha512_update(ref state.hmacsha512, in MemoryMarshal.GetReference(data), (ulong)data.Length);
        }

        private protected override void MacCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(mac.Length == crypto_auth_hmacsha512_BYTES);

            crypto_auth_hmacsha512_init(out crypto_auth_hmacsha512_state state, keyHandle, (UIntPtr)keyHandle.Length);
            crypto_auth_hmacsha512_update(ref state, in MemoryMarshal.GetReference(data), (ulong)data.Length);
            crypto_auth_hmacsha512_final(ref state, ref MemoryMarshal.GetReference(mac));
        }

        private protected override bool TryVerifyCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(mac.Length == crypto_auth_hmacsha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];

            crypto_auth_hmacsha512_init(out crypto_auth_hmacsha512_state state, keyHandle, (UIntPtr)keyHandle.Length);
            crypto_auth_hmacsha512_update(ref state, in MemoryMarshal.GetReference(data), (ulong)data.Length);
            crypto_auth_hmacsha512_final(ref state, ref MemoryMarshal.GetReference(temp));

            return CryptographicOperations.FixedTimeEquals(temp, mac);
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha512_bytes() != (UIntPtr)crypto_auth_hmacsha512_BYTES) ||
                (crypto_auth_hmacsha512_keybytes() != (UIntPtr)crypto_auth_hmacsha512_KEYBYTES) ||
                (crypto_auth_hmacsha512_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha512_state>()))
            {
                throw Error.Cryptographic_InitializationFailed(8837.ToString("X"));
            }
        }
    }
}
