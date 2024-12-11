using NSec.Cryptography.Formatting;
using System;
using System.Diagnostics;
using System.Threading;
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
    public sealed class Aes256GcmDetached : AeadDetachedAlgorithm
    {
        private const uint NSecBlobHeader = 0xDE6144DE;

        private static int s_isSupported;
        private static int s_selfTest;

        public Aes256GcmDetached() : base(
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
                throw Error.PlatformNotSupported_Aes256Gcm();
            }
        }

        public static bool IsSupported
        {
            get
            {
                if (s_isSupported == 0)
                {
                    Sodium.Initialize();
                    Interlocked.Exchange(ref s_isSupported, crypto_aead_aes256gcm_is_available() != 0 ? 1 : -1);
                }
                return s_isSupported > 0;
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out PublicKey? publicKey)
        {
            Debug.Assert(seed.Length == crypto_aead_aes256gcm_KEYBYTES);

            publicKey = null;
            keyHandle = SecureMemoryHandle.CreateFrom(seed);
        }

        private protected override void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag)
        {
            Debug.Assert(keyHandle.Size == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length);
            Debug.Assert(tag.Length == crypto_aead_aes256gcm_ABYTES);
            Debug.Assert(!tag.IsEmpty);

            int error = crypto_aead_aes256gcm_encrypt_detached(
                ciphertext,
                tag,
                out ulong maclen,
                plaintext,
                (ulong)plaintext.Length,
                associatedData,
                (ulong)associatedData.Length,
                IntPtr.Zero,
                nonce,
                keyHandle);

            Debug.Assert(error == 0);
            Debug.Assert((ulong)tag.Length == maclen);
        }

        internal override int GetSeedSize()
        {
            return crypto_aead_aes256gcm_KEYBYTES;
        }

        private protected override bool DecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle.Size == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length);
            Debug.Assert(tag.Length == crypto_aead_aes256gcm_ABYTES);
            Debug.Assert(!tag.IsEmpty);

            int error = crypto_aead_aes256gcm_decrypt_detached(
                plaintext,
                IntPtr.Zero,
                ciphertext,
                (ulong)ciphertext.Length,
                tag,
                associatedData,
                (ulong)associatedData.Length,
                nonce,
                keyHandle);

            return error == 0;
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
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryExport(NSecBlobHeader, crypto_aead_aes256gcm_KEYBYTES, crypto_aead_aes256gcm_ABYTES, keyHandle, blob, out blobSize),
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
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(crypto_aead_aes256gcm_KEYBYTES, blob, out keyHandle),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryImport(NSecBlobHeader, crypto_aead_aes256gcm_KEYBYTES, crypto_aead_aes256gcm_ABYTES, blob, out keyHandle),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static void SelfTest()
        {
            if ((crypto_aead_aes256gcm_abytes() != crypto_aead_aes256gcm_ABYTES) ||
                (crypto_aead_aes256gcm_keybytes() != crypto_aead_aes256gcm_KEYBYTES) ||
                (crypto_aead_aes256gcm_npubbytes() != crypto_aead_aes256gcm_NPUBBYTES) ||
                (crypto_aead_aes256gcm_nsecbytes() != crypto_aead_aes256gcm_NSECBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
