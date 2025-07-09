using System;
using System.Diagnostics;
using System.Threading;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  AEGIS-256
    //
    //      The AEGIS-256 authenticated encryption with associated data (AEAD)
    //      algorithm
    //
    //  References:
    //
    //      draft-irtf-cfrg-aegis-aead-04 - The AEGIS Family of Authenticated
    //          Encryption Algorithms
    //
    //      RFC 5116 - An Interface and Algorithms for Authenticated Encryption
    //
    //  Parameters:
    //
    //      Key Size - 32 bytes.
    //
    //      Nonce Size - 32 bytes.
    //
    //      Tag Size - 32 bytes.
    //
    //      Plaintext Size - Between 0 and 2^61-1 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
    //
    //      Associated Data Size - Between 0 and 2^64-1 bytes.
    //
    //      Ciphertext Size - The ciphertext always has the size of the
    //          plaintext plus the tag size.
    //
    public sealed class Aegis256 : AeadAlgorithm
    {
        private const uint NSecBlobHeader = 0xDE614BDE;

        private static int s_selfTest;

        public Aegis256() : base(
            keySize: crypto_aead_aegis256_KEYBYTES,
            nonceSize: crypto_aead_aegis256_NPUBBYTES,
            tagSize: crypto_aead_aegis256_ABYTES)
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
            Debug.Assert(seed.Length == crypto_aead_aegis256_KEYBYTES);

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
            Debug.Assert(keyHandle.Size == crypto_aead_aegis256_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aegis256_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_aegis256_ABYTES);

            int error = crypto_aead_aegis256_encrypt(
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
            return crypto_aead_aegis256_KEYBYTES;
        }

        private protected override bool DecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle.Size == crypto_aead_aegis256_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aegis256_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_aegis256_ABYTES);

            int error = crypto_aead_aegis256_decrypt(
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
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryExport(NSecBlobHeader, crypto_aead_aegis256_KEYBYTES, crypto_aead_aegis256_ABYTES, keyHandle, blob, out blobSize),
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
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(crypto_aead_aegis256_KEYBYTES, blob, out keyHandle),
                KeyBlobFormat.NSecSymmetricKey => NSecKeyFormatter.TryImport(NSecBlobHeader, crypto_aead_aegis256_KEYBYTES, crypto_aead_aegis256_ABYTES, blob, out keyHandle),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static void SelfTest()
        {
            if ((crypto_aead_aegis256_abytes() != crypto_aead_aegis256_ABYTES) ||
                (crypto_aead_aegis256_keybytes() != crypto_aead_aegis256_KEYBYTES) ||
                (crypto_aead_aegis256_npubbytes() != crypto_aead_aegis256_NPUBBYTES) ||
                (crypto_aead_aegis256_nsecbytes() != crypto_aead_aegis256_NSECBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
