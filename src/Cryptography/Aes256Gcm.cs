using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  AES256-GCM
    //
    //      Authenticated Encryption with Associated Data (AEAD) algorithm
    //      based on the Advanced Encryption Standard (AES) in Galois/Counter
    //      Mode (GCM) with 256-bit keys
    //
    //  References:
    //
    //      FIPS 197 - Advanced Encryption Standard (AES)
    //
    //      NIST SP 800-38D - Recommendation for Block Cipher Modes of
    //          Operation: Galois/Counter Mode (GCM) and GMAC
    //
    //      RFC 5116 - An Interface and Algorithms for Authenticated Encryption
    //
    //  Parameters:
    //
    //      Key Size - 32 bytes.
    //
    //      Nonce Size - 12 bytes.
    //
    //      Tag Size - 16 bytes.
    //
    //      Plaintext Size - Between 0 and 2^36-31 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
    //
    //      Associated Data Size - Between 0 and 2^61-1 bytes.
    //
    //      Ciphertext Size - The ciphertext always has the size of the
    //          plaintext plus the tag size.
    //
    public sealed class Aes256Gcm : AeadAlgorithm
    {
        private const uint NSecBlobHeader = 0xDE6144DE;

        private static int s_isSupported;
        private static int s_selfTest;

        public Aes256Gcm() : base(
            keySize: crypto_aead_aes256gcm_KEYBYTES,
            nonceSize: crypto_aead_aes256gcm_NPUBBYTES,
            tagSize: crypto_aead_aes256gcm_ABYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
            if (s_isSupported == 0)
            {
                Interlocked.Exchange(ref s_isSupported, crypto_aead_aes256gcm_is_available() != 0 ? 1 : -1);
            }
            if (s_isSupported < 0)
            {
                throw Error.PlatformNotSupported_Algorithm();
            }
        }

        public static bool IsSupported
        {
            get
            {
                int isSupported = s_isSupported;
                if (isSupported == 0)
                {
                    Sodium.Initialize();
                    Interlocked.Exchange(ref s_isSupported, crypto_aead_aes256gcm_is_available() != 0 ? 1 : -1);
                    isSupported = s_isSupported;
                }
                return isSupported > 0;
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey? publicKey)
        {
            Debug.Assert(seed.Length == crypto_aead_aes256gcm_KEYBYTES);

            publicKey = null;
            owner = memoryPool.Rent(seed.Length);
            memory = owner.Memory.Slice(0, seed.Length);
            seed.CopyTo(owner.Memory.Span);
        }

        private protected unsafe override void EncryptCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(key.Length == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_aes256gcm_ABYTES);

            fixed (byte* c = ciphertext)
            fixed (byte* m = plaintext)
            fixed (byte* ad = associatedData)
            fixed (Nonce* n = &nonce)
            fixed (byte* k = key)
            {
                int error = crypto_aead_aes256gcm_encrypt(
                    c,
                    out ulong clen_p,
                    m,
                    (ulong)plaintext.Length,
                    ad,
                    (ulong)associatedData.Length,
                    null,
                    n,
                    k);

                Debug.Assert(error == 0);
                Debug.Assert((ulong)ciphertext.Length == clen_p);
            }
        }

        internal override int GetSeedSize()
        {
            return crypto_aead_aes256gcm_KEYBYTES;
        }

        private protected unsafe override bool DecryptCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(key.Length == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_aes256gcm_ABYTES);

            fixed (byte* m = plaintext)
            fixed (byte* c = ciphertext)
            fixed (byte* ad = associatedData)
            fixed (Nonce* n = &nonce)
            fixed (byte* k = key)
            {
                int error = crypto_aead_aes256gcm_decrypt(
                    m,
                    out ulong mlen_p,
                    null,
                    c,
                    (ulong)ciphertext.Length,
                    ad,
                    (ulong)associatedData.Length,
                    n,
                    k);

                // libsodium clears plaintext if decryption fails

                Debug.Assert(error != 0 || (ulong)plaintext.Length == mlen_p);
                return error == 0;
            }
        }

        internal override bool TryExportKey(
            ReadOnlySpan<byte> key,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            return format switch
            {
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryExport(key, blob, out blobSize),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryExport(NSecBlobHeader, KeySize, TagSize, key, blob, out blobSize),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte>? owner,
            out PublicKey? publicKey)
        {
            publicKey = null;

            return format switch
            {
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(KeySize, blob, memoryPool, out memory, out owner),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, TagSize, blob, memoryPool, out memory, out owner),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static void SelfTest()
        {
            if ((crypto_aead_aes256gcm_abytes() != (UIntPtr)crypto_aead_aes256gcm_ABYTES) ||
                (crypto_aead_aes256gcm_keybytes() != (UIntPtr)crypto_aead_aes256gcm_KEYBYTES) ||
                (crypto_aead_aes256gcm_npubbytes() != (UIntPtr)crypto_aead_aes256gcm_NPUBBYTES) ||
                (crypto_aead_aes256gcm_nsecbytes() != (UIntPtr)crypto_aead_aes256gcm_NSECBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
