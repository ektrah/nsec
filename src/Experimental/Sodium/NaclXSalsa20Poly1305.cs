using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using NSec.Cryptography;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Experimental.Sodium
{
    public sealed class NaclXSalsa20Poly1305 : NaclSecretBoxAlgorithm
    {
        private const uint NSecBlobHeader = 0xDE6A4DDE;

        private static int s_selfTest;

        public NaclXSalsa20Poly1305() : base(
            keySize: crypto_secretbox_xsalsa20poly1305_KEYBYTES,
            nonceSize: crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
            macSize: crypto_secretbox_xsalsa20poly1305_MACBYTES)
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
            out PublicKey? publicKey)
        {
            Debug.Assert(seed.Length == crypto_secretbox_xsalsa20poly1305_KEYBYTES);

            publicKey = null;
            keyHandle = SecureMemoryHandle.CreateFrom(seed);
        }

        internal override void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle.Size == crypto_secretbox_xsalsa20poly1305_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
            Debug.Assert(ciphertext.Length == crypto_secretbox_xsalsa20poly1305_MACBYTES + plaintext.Length);

            int error = crypto_secretbox_easy(
                ciphertext,
                plaintext,
                (ulong)plaintext.Length,
                nonce,
                keyHandle);

            Debug.Assert(error == 0);
        }

        internal override int GetSeedSize()
        {
            return crypto_secretbox_xsalsa20poly1305_KEYBYTES;
        }

        internal override bool DecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle.Size == crypto_secretbox_xsalsa20poly1305_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_secretbox_xsalsa20poly1305_MACBYTES);

            int error = crypto_secretbox_open_easy(
                plaintext,
                ciphertext,
                (ulong)ciphertext.Length,
                nonce,
                keyHandle);

            // TODO: clear plaintext if decryption fails

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
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryExport(NSecBlobHeader, crypto_secretbox_xsalsa20poly1305_KEYBYTES, crypto_secretbox_xsalsa20poly1305_MACBYTES, keyHandle, blob, out blobSize),
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
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(crypto_secretbox_xsalsa20poly1305_KEYBYTES, blob, out keyHandle),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryImport(NSecBlobHeader, crypto_secretbox_xsalsa20poly1305_KEYBYTES, crypto_secretbox_xsalsa20poly1305_MACBYTES, blob, out keyHandle),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static void SelfTest()
        {
            if ((crypto_secretbox_keybytes() != crypto_secretbox_xsalsa20poly1305_KEYBYTES) ||
                (crypto_secretbox_macbytes() != crypto_secretbox_xsalsa20poly1305_MACBYTES) ||
                (crypto_secretbox_noncebytes() != crypto_secretbox_xsalsa20poly1305_NONCEBYTES) ||
                (Marshal.PtrToStringAnsi(crypto_secretbox_primitive()) != crypto_secretbox_PRIMITIVE))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
