using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
        public static readonly int MinKeySize = crypto_auth_hmacsha512_KEYBYTES;
        public static readonly int MaxKeySize = crypto_hash_sha512_BYTES;
        public static readonly int MinMacSize = 16;
        public static readonly int MaxMacSize = crypto_auth_hmacsha512_BYTES;

        private const uint NSecBlobHeader = 0xDE6347DE;

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

        internal override void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac)
        {
            Debug.Assert(mac.Length <= crypto_auth_hmacsha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];

            int error = crypto_auth_hmacsha512_final(
                ref state.hmacsha512,
                temp);

            Debug.Assert(error == 0);

            temp[..mac.Length].CopyTo(mac);
        }

        internal override int GetSeedSize()
        {
            return KeySize;
        }

        internal override void InitializeCore(
            SecureMemoryHandle keyHandle,
            out IncrementalMacState state)
        {
            Debug.Assert(keyHandle.Size <= crypto_hash_sha512_BYTES);

            int error = crypto_auth_hmacsha512_init(
                ref state.hmacsha512,
                keyHandle,
                (nuint)keyHandle.Size);

            Debug.Assert(error == 0);
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

        internal override void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data)
        {
            int error = crypto_auth_hmacsha512_update(
                ref state.hmacsha512,
                data,
                (ulong)data.Length);

            Debug.Assert(error == 0);
        }

        private protected override void MacCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(keyHandle.Size <= crypto_hash_sha512_BYTES);
            Debug.Assert(mac.Length <= crypto_auth_hmacsha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];
            crypto_auth_hmacsha512_state state;

            crypto_auth_hmacsha512_init(
                ref state,
                keyHandle,
                (nuint)keyHandle.Size);

            crypto_auth_hmacsha512_update(
                ref state,
                data,
                (ulong)data.Length);

            crypto_auth_hmacsha512_final(
                ref state,
                temp);

            temp[..mac.Length].CopyTo(mac);
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha512_bytes() != crypto_auth_hmacsha512_BYTES) ||
                (crypto_auth_hmacsha512_keybytes() != crypto_auth_hmacsha512_KEYBYTES) ||
                (crypto_auth_hmacsha512_statebytes() != (nuint)Unsafe.SizeOf<crypto_auth_hmacsha512_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
