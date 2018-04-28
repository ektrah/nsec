using System;
using System.Buffers;
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
        public static readonly int MinKeySize = crypto_hash_sha512_BYTES;
        public static readonly int MaxKeySize = crypto_hash_sha512_BYTES;
        public static readonly int MinMacSize = crypto_auth_hmacsha512_BYTES;
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
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            publicKey = null;
            owner = memoryPool.Rent(seed.Length);
            memory = owner.Memory.Slice(0, seed.Length);
            seed.CopyTo(owner.Memory.Span);
        }

        internal override bool FinalizeAndVerifyCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(mac.Length == crypto_auth_hmacsha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];

            int error = crypto_auth_hmacsha512_final(
                ref state.hmacsha512,
                ref temp.GetPinnableReference());

            Debug.Assert(error == 0);

            return CryptographicOperations.FixedTimeEquals(temp, mac);
        }

        internal override void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac)
        {
            Debug.Assert(mac.Length == crypto_auth_hmacsha512_BYTES);

            int error = crypto_auth_hmacsha512_final(
                ref state.hmacsha512,
                ref mac.GetPinnableReference());

            Debug.Assert(error == 0);
        }

        internal override int GetSeedSize()
        {
            return KeySize;
        }

        internal override void InitializeCore(
            ReadOnlySpan<byte> key,
            int macSize,
            out IncrementalMacState state)
        {
            Debug.Assert(key.Length == crypto_hash_sha512_BYTES);
            Debug.Assert(macSize == crypto_auth_hmacsha512_BYTES);

            int error = crypto_auth_hmacsha512_init(
                out state.hmacsha512,
                in key.GetPinnableReference(),
                (UIntPtr)key.Length);

            Debug.Assert(error == 0);
        }

        internal override bool TryExportKey(
            ReadOnlySpan<byte> key,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return RawKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.NSecSymmetricKey:
                return NSecKeyFormatter.TryExport(NSecBlobHeader, KeySize, MacSize, key, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            publicKey = null;

            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return RawKeyFormatter.TryImport(KeySize, blob, memoryPool, out memory, out owner);
            case KeyBlobFormat.NSecSymmetricKey:
                return NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, MacSize, blob, memoryPool, out memory, out owner);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data)
        {
            int error = crypto_auth_hmacsha512_update(
                ref state.hmacsha512,
                in data.GetPinnableReference(),
                (ulong)data.Length);

            Debug.Assert(error == 0);
        }

        private protected override void MacCore(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            Debug.Assert(key.Length == crypto_hash_sha512_BYTES);
            Debug.Assert(mac.Length == crypto_auth_hmacsha512_BYTES);

            crypto_auth_hmacsha512_init(out crypto_auth_hmacsha512_state state, in key.GetPinnableReference(), (UIntPtr)key.Length);
            crypto_auth_hmacsha512_update(ref state, in data.GetPinnableReference(), (ulong)data.Length);
            crypto_auth_hmacsha512_final(ref state, ref mac.GetPinnableReference());
        }

        private protected override bool VerifyCore(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            Debug.Assert(key.Length == crypto_hash_sha512_BYTES);
            Debug.Assert(mac.Length == crypto_auth_hmacsha512_BYTES);

            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha512_BYTES];

            crypto_auth_hmacsha512_init(out crypto_auth_hmacsha512_state state, in key.GetPinnableReference(), (UIntPtr)key.Length);
            crypto_auth_hmacsha512_update(ref state, in data.GetPinnableReference(), (ulong)data.Length);
            crypto_auth_hmacsha512_final(ref state, ref temp.GetPinnableReference());

            return CryptographicOperations.FixedTimeEquals(temp, mac);
        }

        private static void SelfTest()
        {
            if ((crypto_auth_hmacsha512_bytes() != (UIntPtr)crypto_auth_hmacsha512_BYTES) ||
                (crypto_auth_hmacsha512_keybytes() != (UIntPtr)crypto_auth_hmacsha512_KEYBYTES) ||
                (crypto_auth_hmacsha512_statebytes() != (UIntPtr)Unsafe.SizeOf<crypto_auth_hmacsha512_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
