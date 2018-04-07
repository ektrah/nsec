using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using NSec.Cryptography;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Experimental.Sodium
{
    public sealed class XChaCha20Poly1305 : AeadAlgorithm
    {
        private const uint NSecBlobHeader = 0xDE6148DE;

        private static int s_selfTest;

        public XChaCha20Poly1305() : base(
            keySize: crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
            nonceSize: crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
            tagSize: crypto_aead_xchacha20poly1305_ietf_ABYTES)
        {
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
            Debug.Assert(seed.Length == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

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
            Debug.Assert(keyHandle.Length == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_xchacha20poly1305_ietf_ABYTES);

            crypto_aead_xchacha20poly1305_ietf_encrypt(
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

        internal override int GetSeedSize()
        {
            return crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
        }

        private protected override bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_xchacha20poly1305_ietf_ABYTES);

            int error = crypto_aead_xchacha20poly1305_ietf_decrypt(
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
            if ((crypto_aead_xchacha20poly1305_ietf_abytes() != (UIntPtr)crypto_aead_xchacha20poly1305_ietf_ABYTES) ||
                (crypto_aead_xchacha20poly1305_ietf_keybytes() != (UIntPtr)crypto_aead_xchacha20poly1305_ietf_KEYBYTES) ||
                (crypto_aead_xchacha20poly1305_ietf_npubbytes() != (UIntPtr)crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) ||
                (crypto_aead_xchacha20poly1305_ietf_nsecbytes() != (UIntPtr)crypto_aead_xchacha20poly1305_ietf_NSECBYTES))
            {
                throw Error.Cryptographic_InitializationFailed();
            }
        }
    }
}
