using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
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
    //      RFC 5084 - Using AES-CCM and AES-GCM Authenticated Encryption in the
    //          Cryptographic Message Syntax (CMS)
    //
    //  Parameters:
    //
    //      Key Size - 32 bytes.
    //
    //      Nonce Size - 12 bytes.
    //
    //      Tag Size - 16 bytes.
    //
    //      Plaintext Size - Between 0 and 2^36-31 bytes. (A Span<byte> can only
    //          hold up to 2^31-1 bytes.)
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
            out SecureMemoryHandle keyHandle,
            out PublicKey publicKey)
        {
            Debug.Assert(seed.Length == crypto_aead_aes256gcm_KEYBYTES);

            publicKey = null;
            SecureMemoryHandle.Import(seed, out keyHandle);
        }

        private protected override void EncryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_aes256gcm_ABYTES);

            crypto_aead_aes256gcm_encrypt(
                ref MemoryMarshal.GetReference(ciphertext),
                out ulong ciphertextLength,
                in MemoryMarshal.GetReference(plaintext),
                (ulong)plaintext.Length,
                in MemoryMarshal.GetReference(associatedData),
                (ulong)associatedData.Length,
                IntPtr.Zero,
                in nonce,
                keyHandle);

            Debug.Assert((ulong)ciphertext.Length == ciphertextLength);
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_aead_aes256gcm_KEYBYTES;
        }

        private protected override bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_aes256gcm_ABYTES);

            int error = crypto_aead_aes256gcm_decrypt(
                ref MemoryMarshal.GetReference(plaintext),
                out ulong plaintextLength,
                IntPtr.Zero,
                in MemoryMarshal.GetReference(ciphertext),
                (ulong)ciphertext.Length,
                in MemoryMarshal.GetReference(associatedData),
                (ulong)associatedData.Length,
                in nonce,
                keyHandle);

            // libsodium clears the plaintext if decryption fails.

            Debug.Assert(error != 0 || (ulong)plaintext.Length == plaintextLength);
            return error == 0;
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
                return NSecKeyFormatter.TryExport(NSecBlobHeader, KeySize, TagSize, keyHandle, blob, out blobSize);
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
                return NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, TagSize, blob, out keyHandle);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        private static void SelfTest()
        {
            if ((crypto_aead_aes256gcm_abytes() != (UIntPtr)crypto_aead_aes256gcm_ABYTES) ||
                (crypto_aead_aes256gcm_keybytes() != (UIntPtr)crypto_aead_aes256gcm_KEYBYTES) ||
                (crypto_aead_aes256gcm_npubbytes() != (UIntPtr)crypto_aead_aes256gcm_NPUBBYTES) ||
                (crypto_aead_aes256gcm_nsecbytes() != (UIntPtr)crypto_aead_aes256gcm_NSECBYTES))
            {
                throw Error.Cryptographic_InitializationFailed(9539.ToString("X"));
            }
        }
    }
}
