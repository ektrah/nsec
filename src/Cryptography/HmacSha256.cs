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
    //      RFC 4231 - Identifiers and Test Vectors for HMAC-SHA-224,
    //          HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
    //
    //  Parameters:
    //
    //      Key Size - The key for HMAC-SHA-256 can be of any length. A length
    //          less than L=32 bytes (the output length of SHA-256) is strongly
    //          discouraged. Keys longer than L do not significantly increase
    //          the function strength.
    //
    //      MAC Size - 32 bytes. The output can be truncated to 16 bytes
    //          (128 bits of security).
    //
    public sealed class HmacSha256 : MacAlgorithm
    {
        public static readonly int MinKeySize = crypto_hash_sha256_BYTES;
        public static readonly int MaxKeySize = crypto_hash_sha256_BYTES;
        public static readonly int MinMacSize = crypto_auth_hmacsha256_BYTES;
        public static readonly int MaxMacSize = crypto_auth_hmacsha256_BYTES;

        private const uint NSecBlobHeader = 0xDE3346DE;

        private static int s_selfTest;

        public HmacSha256() : this(
            keySize: crypto_hash_sha256_BYTES,
            macSize: crypto_auth_hmacsha256_BYTES)
        {
        }

        public HmacSha256(int keySize, int macSize) : base(
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
            publicKey = default;
            SecureMemoryHandle.Import(seed, out keyHandle);
        }

        internal override bool FinalizeAndTryVerifyCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(mac.Length == crypto_auth_hmacsha256_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];

            crypto_auth_hmacsha256_final(ref state.hmacsha256, ref MemoryMarshal.GetReference(temp));

            return CryptographicOperations.FixedTimeEquals(temp, mac);
        }

        internal override void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac)
        {
            Debug.Assert(mac.Length == crypto_auth_hmacsha256_BYTES);

            crypto_auth_hmacsha256_final(ref state.hmacsha256, ref MemoryMarshal.GetReference(mac));
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
            Debug.Assert(macSize == crypto_auth_hmacsha256_BYTES);

            crypto_auth_hmacsha256_init(out state.hmacsha256, keyHandle, (UIntPtr)keyHandle.Length);
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
                return RawKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            case KeyBlobFormat.NSecSymmetricKey:
                return NSecKeyFormatter.TryExport(NSecBlobHeader, keyHandle, blob, out blobSize);
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
                return RawKeyFormatter.TryImport(KeySize, blob, out keyHandle);
            case KeyBlobFormat.NSecSymmetricKey:
                return NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, blob, out keyHandle);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data)
        {
            crypto_auth_hmacsha256_update(ref state.hmacsha256, in MemoryMarshal.GetReference(data), (ulong)data.Length);
        }

        private protected override void MacCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(mac.Length == crypto_auth_hmacsha256_BYTES);

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, keyHandle, (UIntPtr)keyHandle.Length);
            crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(data), (ulong)data.Length);
            crypto_auth_hmacsha256_final(ref state, ref MemoryMarshal.GetReference(mac));
        }

        private protected override bool TryVerifyCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(mac.Length == crypto_auth_hmacsha256_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];

            crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, keyHandle, (UIntPtr)keyHandle.Length);
            crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(data), (ulong)data.Length);
            crypto_auth_hmacsha256_final(ref state, ref MemoryMarshal.GetReference(temp));

            return CryptographicOperations.FixedTimeEquals(temp, mac);
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha256_bytes() != (UIntPtr)crypto_auth_hmacsha256_BYTES) ||
                (crypto_auth_hmacsha256_keybytes() != (UIntPtr)crypto_auth_hmacsha256_KEYBYTES) ||
                (crypto_auth_hmacsha256_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha256_state>()))
            {
                throw Error.Cryptographic_InitializationFailed(8933.ToString("X"));
            }
        }
    }
}
