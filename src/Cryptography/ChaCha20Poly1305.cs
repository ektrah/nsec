using System;
using System.Diagnostics;
using System.Threading;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  ChaCha20-Poly1305
    //
    //      Authenticated Encryption with Associated Data (AEAD) algorithm
    //      based the ChaCha20 stream cipher and the Poly1305 authenticator
    //
    //  References:
    //
    //      RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols
    //
    //      RFC 5116 - An Interface and Algorithms for Authenticated Encryption
    //
    //  Parameters:
    //
    //      Key Size - 32 bytes.
    //
    //      Nonce Size - 12 bytes, i.e., what libsodium calls the IETF variant
    //          of ChaCha20-Poly1305.
    //
    //      Tag Size - 16 bytes.
    //
    //      Plaintext Size - Between 0 and 2^38-64 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
    //
    //      Associated Data Size - Between 0 and 2^64-1 bytes.
    //
    //      Ciphertext Size - The ciphertext always has the size of the
    //          plaintext plus the tag size.
    //
    public sealed class ChaCha20Poly1305 : AeadAlgorithm
    {
        private const uint NSecBlobHeader = 0xDE6143DE;

        private static int s_selfTest;

        public ChaCha20Poly1305() : base(
            keySize: crypto_aead_chacha20poly1305_ietf_KEYBYTES,
            nonceSize: crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
            tagSize: crypto_aead_chacha20poly1305_ietf_ABYTES)
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
            Debug.Assert(seed.Length == crypto_aead_chacha20poly1305_ietf_KEYBYTES);

            publicKey = null;
            keyHandle = SecureMemoryHandle.CreateFrom(seed);
        }

        private protected override void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle.Size == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_chacha20poly1305_ietf_ABYTES);

            int error = crypto_aead_chacha20poly1305_ietf_encrypt(
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
            return crypto_aead_chacha20poly1305_ietf_KEYBYTES;
        }

        private protected override bool DecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle.Size == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_chacha20poly1305_ietf_ABYTES);

            int error = crypto_aead_chacha20poly1305_ietf_decrypt(
                plaintext,
                out ulong plaintextLength,
                IntPtr.Zero,
                ciphertext,
                (ulong)ciphertext.Length,
                associatedData,
                (ulong)associatedData.Length,
                nonce,
                keyHandle);

            // libsodium clears plaintext if decryption fails

            Debug.Assert(error != 0 || (ulong)plaintext.Length == plaintextLength);
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
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryExport(NSecBlobHeader, crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_ietf_ABYTES, keyHandle, blob, out blobSize),
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
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(crypto_aead_chacha20poly1305_ietf_KEYBYTES, blob, out keyHandle),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryImport(NSecBlobHeader, crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_ietf_ABYTES, blob, out keyHandle),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static void SelfTest()
        {
            if ((crypto_aead_chacha20poly1305_ietf_abytes() != crypto_aead_chacha20poly1305_ietf_ABYTES) ||
                (crypto_aead_chacha20poly1305_ietf_keybytes() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) ||
                (crypto_aead_chacha20poly1305_ietf_npubbytes() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES) ||
                (crypto_aead_chacha20poly1305_ietf_nsecbytes() != crypto_aead_chacha20poly1305_ietf_NSECBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
