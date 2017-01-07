using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  AES-256-GCM
    //
    //      Authenticated Encryption with Associated Data (AEAD) algorithm
    //      based on the Advanced Encryption Standard (AES) in Galois/Counter
    //      Mode (GCM) with 256-bit keys
    //
    //  References:
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
    //      Plaintext Size - Between 0 and 2^36-31 bytes. Since a Span<byte> can
    //          hold between 0 to 2^31-1 bytes, we do not check the length of
    //          plaintext inputs.
    //
    //      Associated Data Size - Between 0 and 2^61-1 bytes. Since a
    //          Span<byte> can hold between 0 to 2^31-1 bytes, we do not check
    //          the length of associated data inputs.
    //
    //      Ciphertext Size - The ciphertext always has the size of the
    //          plaintext plus the tag size.
    //
    public sealed class Aes256Gcm : AeadAlgorithm
    {
        private static readonly Lazy<int> s_isAvailable = new Lazy<int>(new Func<int>(crypto_aead_aes256gcm_is_available));
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        private static readonly KeyFormatter s_nsecKeyFormatter =
            new KeyFormatter(crypto_aead_aes256gcm_KEYBYTES, new byte[]
        {
            0x7F, 0x31, 0x44, crypto_aead_aes256gcm_KEYBYTES,
        });

        private static readonly KeyFormatter s_rawKeyFormatter =
            new KeyFormatter(crypto_aead_aes256gcm_KEYBYTES, new byte[] { });

        public Aes256Gcm() : base(
            keySize: crypto_aead_aes256gcm_KEYBYTES,
            minNonceSize: crypto_aead_aes256gcm_NPUBBYTES,
            maxNonceSize: crypto_aead_aes256gcm_NPUBBYTES,
            tagSize: crypto_aead_aes256gcm_ABYTES)
        {
            if (s_isAvailable.Value == 0)
                throw new PlatformNotSupportedException();
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        public static bool IsAvailable => Sodium.TryInitialize() && (s_isAvailable.Value != 0);

        internal override SecureMemoryHandle CreateKey(
            out PublicKey publicKey)
        {
            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(crypto_aead_aes256gcm_KEYBYTES);
            randombytes_buf(handle, (IntPtr)handle.Length);
            publicKey = null;
            return handle;
        }

        internal override void EncryptCore(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.Handle.Length == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_aes256gcm_ABYTES);

            crypto_aead_aes256gcm_encrypt(
                ref ciphertext.DangerousGetPinnableReference(),
                out ulong ciphertextLength,
                ref plaintext.DangerousGetPinnableReference(),
                (ulong)plaintext.Length,
                ref associatedData.DangerousGetPinnableReference(),
                (ulong)associatedData.Length,
                IntPtr.Zero,
                ref nonce.DangerousGetPinnableReference(),
                key.Handle);

            Debug.Assert((ulong)ciphertext.Length == ciphertextLength);
        }

        internal override int GetDerivedKeySize()
        {
            return crypto_aead_aes256gcm_KEYBYTES;
        }

        internal override bool TryDecryptCore(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.Handle.Length == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_aes256gcm_ABYTES);

            int error = crypto_aead_aes256gcm_decrypt(
                ref plaintext.DangerousGetPinnableReference(),
                out ulong plaintextLength,
                IntPtr.Zero,
                ref ciphertext.DangerousGetPinnableReference(),
                (ulong)ciphertext.Length,
                ref associatedData.DangerousGetPinnableReference(),
                (ulong)associatedData.Length,
                ref nonce.DangerousGetPinnableReference(),
                key.Handle);

            // libsodium clears the plaintext if decryption fails, so we do
            // not need to clear the plaintext.

            Debug.Assert(error != 0 || (ulong)plaintext.Length == plaintextLength);
            return error == 0;
        }

        internal override bool TryExportKey(
            Key key,
            KeyBlobFormat format,
            out byte[] result)
        {
            Debug.Assert(key != null);

            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryExport(key, out result);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryExport(key, out result);
            default:
                result = null;
                return false;
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            KeyFlags flags,
            out Key result)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryImport(this, flags, blob, out result);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryImport(this, flags, blob, out result);
            default:
                result = null;
                return false;
            }
        }

        private static bool SelfTest()
        {
            return (crypto_aead_aes256gcm_abytes() == (IntPtr)crypto_aead_aes256gcm_ABYTES)
                && (crypto_aead_aes256gcm_keybytes() == (IntPtr)crypto_aead_aes256gcm_KEYBYTES)
                && (crypto_aead_aes256gcm_npubbytes() == (IntPtr)crypto_aead_aes256gcm_NPUBBYTES)
                && (crypto_aead_aes256gcm_nsecbytes() == (IntPtr)crypto_aead_aes256gcm_NSECBYTES);
        }
    }
}
