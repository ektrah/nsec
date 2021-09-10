using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
        public static readonly int MinMacSize = 16;
        public static readonly int MaxMacSize = crypto_auth_hmacsha256_BYTES;

        private const uint NSecBlobHeader = 0xDE6346DE;

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
                throw Error.ArgumentOutOfRange_KeySize(nameof(keySize), keySize, MinKeySize, MaxKeySize);
            }
            if (macSize < MinMacSize || macSize > MaxMacSize)
            {
                throw Error.ArgumentOutOfRange_MacSize(nameof(macSize), macSize, MaxMacSize, MaxMacSize);
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
            out PublicKey? publicKey)
        {
            publicKey = null;
            keyHandle = SecureMemoryHandle.CreateFrom(seed);
        }

        internal unsafe override void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac)
        {
            Debug.Assert(mac.Length <= crypto_auth_hmacsha256_BYTES);

            byte* temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];

            fixed (crypto_auth_hmacsha256_state* state_ = &state.hmacsha256)
            {
                int error = crypto_auth_hmacsha256_final(
                    state_,
                    temp);

                Debug.Assert(error == 0);
            }

            fixed (byte* @out = mac)
            {
                Unsafe.CopyBlockUnaligned(@out, temp, (uint)mac.Length);
            }
        }

        internal override int GetSeedSize()
        {
            return KeySize;
        }

        internal unsafe override void InitializeCore(
            SecureMemoryHandle keyHandle,
            out IncrementalMacState state)
        {
            Debug.Assert(keyHandle.Size == crypto_hash_sha256_BYTES);

            fixed (crypto_auth_hmacsha256_state* state_ = &state.hmacsha256)
            {
                int error = crypto_auth_hmacsha256_init(
                    state_,
                    keyHandle,
                    (nuint)keyHandle.Size);

                Debug.Assert(error == 0);
            }
        }

        internal override bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            return format switch
            {
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryExport(keyHandle, blob, out blobSize),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryExport(NSecBlobHeader, KeySize, MacSize, keyHandle, blob, out blobSize),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle? keyHandle,
            out PublicKey? publicKey)
        {
            publicKey = null;

            return format switch
            {
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(KeySize, blob, out keyHandle),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, MacSize, blob, out keyHandle),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal unsafe override void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data)
        {
            fixed (crypto_auth_hmacsha256_state* state_ = &state.hmacsha256)
            fixed (byte* @in = data)
            {
                int error = crypto_auth_hmacsha256_update(
                    state_,
                    @in,
                    (ulong)data.Length);

                Debug.Assert(error == 0);
            }
        }

        private protected unsafe override void MacCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle.Size == crypto_hash_sha256_BYTES);
            Debug.Assert(mac.Length <= crypto_auth_hmacsha256_BYTES);

            byte* temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];

            fixed (byte* @in = data)
            {
                crypto_auth_hmacsha256_state state;

                crypto_auth_hmacsha256_init(
                    &state,
                    keyHandle,
                    (nuint)keyHandle.Size);

                crypto_auth_hmacsha256_update(
                    &state,
                    @in,
                    (ulong)data.Length);

                crypto_auth_hmacsha256_final(
                    &state,
                    temp);
            }

            fixed (byte* @out = mac)
            {
                Unsafe.CopyBlockUnaligned(@out, temp, (uint)mac.Length);
            }
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha256_bytes() != crypto_auth_hmacsha256_BYTES) ||
                (crypto_auth_hmacsha256_keybytes() != crypto_auth_hmacsha256_KEYBYTES) ||
                (crypto_auth_hmacsha256_statebytes() != (nuint)Unsafe.SizeOf<crypto_auth_hmacsha256_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
