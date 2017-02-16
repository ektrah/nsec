using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;
using static Interop.Norx3241;

namespace NSec.Cryptography
{
    public sealed class Norx3241 : AeadAlgorithm
    {
        private static readonly KeyFormatter s_rawKeyFormatter =
            new KeyFormatter(crypto_aead_norx3241_KEYBYTES, new byte[] { });

        private static readonly KeyBlobFormat[] s_supportedKeyBlobFormats =
        {
            KeyBlobFormat.RawSymmetricKey,
        };

        public Norx3241() : base(
            keySize: crypto_aead_norx3241_KEYBYTES,
            nonceSize: crypto_aead_norx3241_NPUBBYTES,
            tagSize: crypto_aead_norx3241_ABYTES)
        {
        }

        internal override void CreateKey(
            SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            publicKeyBytes = null;
        }

        internal override void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_norx3241_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_norx3241_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_norx3241_ABYTES);

            crypto_aead_norx3241_encrypt(
                ref ciphertext.DangerousGetPinnableReference(),
                out ulong ciphertextLength,
                ref plaintext.DangerousGetPinnableReference(),
                (ulong)plaintext.Length,
                ref associatedData.DangerousGetPinnableReference(),
                (ulong)associatedData.Length,
                IntPtr.Zero,
                ref nonce.DangerousGetPinnableReference(),
                keyHandle);

            Debug.Assert((ulong)ciphertext.Length == ciphertextLength);
        }

        internal override int ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob)
        {
            Debug.Assert(keyHandle != null);

            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.Export(keyHandle, blob);
            default:
                throw new FormatException();
            }
        }

        internal override int GetDefaultKeySize()
        {
            return crypto_aead_norx3241_KEYBYTES;
        }

        internal override int GetKeyBlobSize(
            KeyBlobFormat format)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.BlobSize;
            default:
                throw new FormatException();
            }
        }

        internal override ReadOnlySpan<KeyBlobFormat> GetSupportedKeyBlobFormats()
        {
            return s_supportedKeyBlobFormats;
        }

        internal override bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_norx3241_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_norx3241_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_norx3241_ABYTES);

            int error = crypto_aead_norx3241_decrypt(
                ref plaintext.DangerousGetPinnableReference(),
                out ulong plaintextLength,
                IntPtr.Zero,
                ref ciphertext.DangerousGetPinnableReference(),
                (ulong)ciphertext.Length,
                ref associatedData.DangerousGetPinnableReference(),
                (ulong)associatedData.Length,
                ref nonce.DangerousGetPinnableReference(),
                keyHandle);

            Debug.Assert(error != 0 || (ulong)plaintext.Length == plaintextLength);
            return error == 0;
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            default:
                keyHandle = null;
                publicKeyBytes = null;
                return false;
            }
        }
    }
}
