using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography.Experimental
{
    public sealed class NaclXSalsa20Poly1305 : NaclSecretBoxAlgorithm
    {
        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter(crypto_secretbox_xsalsa20poly1305_KEYBYTES, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public NaclXSalsa20Poly1305() : base(
            keySize: crypto_secretbox_xsalsa20poly1305_KEYBYTES,
            nonceSize: crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
            macSize: crypto_secretbox_xsalsa20poly1305_MACBYTES,
            maxPlaintextSize: int.MaxValue - crypto_secretbox_xsalsa20poly1305_MACBYTES)
        {
            if (!s_selfTest.Value)
            {
                throw Error.Cryptographic_InitializationFailed(8513.ToString("X"));
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(seed.Length == crypto_secretbox_xsalsa20poly1305_KEYBYTES);

            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(seed.Length, out keyHandle);
            keyHandle.Import(seed);
        }

        internal override void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_secretbox_xsalsa20poly1305_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
            Debug.Assert(ciphertext.Length == crypto_secretbox_xsalsa20poly1305_MACBYTES + plaintext.Length);

            crypto_secretbox_easy(
                ref MemoryMarshal.GetReference(ciphertext),
                ref MemoryMarshal.GetReference(plaintext),
                (ulong)plaintext.Length,
                ref MemoryMarshal.GetReference(nonce),
                keyHandle);
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_secretbox_xsalsa20poly1305_KEYBYTES;
        }

        internal override bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_secretbox_xsalsa20poly1305_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_secretbox_xsalsa20poly1305_MACBYTES);

            int error = crypto_secretbox_open_easy(
                ref MemoryMarshal.GetReference(plaintext),
                ref MemoryMarshal.GetReference(ciphertext),
                (ulong)ciphertext.Length,
                ref MemoryMarshal.GetReference(nonce),
                keyHandle);

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
                return s_rawKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            case KeyBlobFormat.NSecSymmetricKey: // TODO
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
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
            case KeyBlobFormat.NSecSymmetricKey: // TODO
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        private static bool SelfTest()
        {
            return (crypto_secretbox_keybytes() == (UIntPtr)crypto_secretbox_xsalsa20poly1305_KEYBYTES)
                && (crypto_secretbox_macbytes() == (UIntPtr)crypto_secretbox_xsalsa20poly1305_MACBYTES)
                && (crypto_secretbox_noncebytes() == (UIntPtr)crypto_secretbox_xsalsa20poly1305_NONCEBYTES)
                && (Marshal.PtrToStringAnsi(crypto_secretbox_primitive()) == crypto_secretbox_PRIMITIVE);
        }
    }
}
