using System;
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

        public void EncryptDetached(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> authenticationTag)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != NonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), NonceSize);
            }
            if (ciphertext.Length != plaintext.Length)
            {
                throw new ArgumentException();
            }
            if (ciphertext.Overlaps(plaintext, out int offset) && offset != 0)
            {
                throw Error.Argument_OverlapCiphertext(nameof(ciphertext));
            }
            if (authenticationTag.Length != TagSize)
            {
                throw new ArgumentException();
            }

            SecureMemoryHandle keyHandle = key.Handle;

            Debug.Assert(keyHandle.Size == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length);
            Debug.Assert(authenticationTag.Length == crypto_aead_aes256gcm_ABYTES);

            int error = crypto_aead_aes256gcm_encrypt_detached(
                ciphertext,
                authenticationTag,
                out ulong maclen,
                plaintext,
                (ulong)plaintext.Length,
                associatedData,
                (ulong)associatedData.Length,
                IntPtr.Zero,
                nonce,
                keyHandle);

            Debug.Assert(error == 0);
            Debug.Assert((ulong)authenticationTag.Length == maclen);
        }

        private protected override void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle.Size == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_aes256gcm_ABYTES);

            int error = crypto_aead_aes256gcm_encrypt(
                ciphertext,
                out ulong clen,
                plaintext,
                (ulong)plaintext.Length,
                associatedData,
                (ulong)associatedData.Length,
                IntPtr.Zero,
                nonce,
                keyHandle);

            Debug.Assert(error == 0);
            Debug.Assert((ulong)ciphertext.Length == clen);
        }

        internal override int GetSeedSize()
        {
            return crypto_aead_aes256gcm_KEYBYTES;
        }

        public bool DecryptDetached(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> authenticationTag,
            Span<byte> plaintext)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != NonceSize || authenticationTag.Length != TagSize)
            {
                return false;
            }
            if (plaintext.Length != ciphertext.Length)
            {
                throw new ArgumentException();
            }
            if (plaintext.Overlaps(ciphertext, out int offset) && offset != 0)
            {
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));
            }

            SecureMemoryHandle keyHandle = key.Handle;

            Debug.Assert(keyHandle.Size == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length);
            Debug.Assert(authenticationTag.Length == crypto_aead_aes256gcm_ABYTES);

            int error = crypto_aead_aes256gcm_decrypt_detached(
                plaintext,
                IntPtr.Zero,
                ciphertext,
                (ulong)ciphertext.Length,
                authenticationTag,
                associatedData,
                (ulong)associatedData.Length,
                nonce,
                keyHandle);

            // libsodium clears plaintext if decryption fails

            return error == 0;
        }

        private protected override bool DecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle.Size == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_aes256gcm_ABYTES);

            int error = crypto_aead_aes256gcm_decrypt(
                plaintext,
                out ulong mlen,
                IntPtr.Zero,
                ciphertext,
                (ulong)ciphertext.Length,
                associatedData,
                (ulong)associatedData.Length,
                nonce,
                keyHandle);

            // libsodium clears plaintext if decryption fails

            Debug.Assert(error != 0 || (ulong)plaintext.Length == mlen);
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
