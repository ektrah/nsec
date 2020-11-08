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

        internal unsafe override void EncryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle.Size == crypto_secretbox_xsalsa20poly1305_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
            Debug.Assert(ciphertext.Length == crypto_secretbox_xsalsa20poly1305_MACBYTES + plaintext.Length);

            fixed (byte* c = ciphertext)
            fixed (byte* m = plaintext)
            fixed (Nonce* n = &nonce)
            {
                int error = crypto_secretbox_easy(
                    c,
                    m,
                    (ulong)plaintext.Length,
                    n,
                    keyHandle);

                Debug.Assert(error == 0);
            }
        }

        internal override int GetSeedSize()
        {
            return crypto_secretbox_xsalsa20poly1305_KEYBYTES;
        }

        internal unsafe override bool DecryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle.Size == crypto_secretbox_xsalsa20poly1305_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_secretbox_xsalsa20poly1305_MACBYTES);

            fixed (byte* m = plaintext)
            fixed (byte* c = ciphertext)
            fixed (Nonce* n = &nonce)
            {
                int error = crypto_secretbox_open_easy(
                    m,
                    c,
                    (ulong)ciphertext.Length,
                    n,
                    keyHandle);

                // TODO: clear plaintext if decryption fails

                return error == 0;
            }
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
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryExport(NSecBlobHeader, KeySize, MacSize, keyHandle, blob, out blobSize),
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
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(KeySize, blob, out keyHandle),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, MacSize, blob, out keyHandle),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static void SelfTest()
        {
            if ((crypto_secretbox_keybytes() != (UIntPtr)crypto_secretbox_xsalsa20poly1305_KEYBYTES) ||
                (crypto_secretbox_macbytes() != (UIntPtr)crypto_secretbox_xsalsa20poly1305_MACBYTES) ||
                (crypto_secretbox_noncebytes() != (UIntPtr)crypto_secretbox_xsalsa20poly1305_NONCEBYTES) ||
                (Marshal.PtrToStringAnsi(crypto_secretbox_primitive()) != crypto_secretbox_PRIMITIVE))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
