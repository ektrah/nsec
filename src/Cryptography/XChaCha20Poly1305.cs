using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  XChaCha20-Poly1305
    //
    //      Authenticated Encryption with Associated Data (AEAD) algorithm
    //      based the ChaCha20 stream cipher and the Poly1305 authenticator
    //
    //  References:
    //
    //      RFC 7539 - ChaCha20 and Poly1305 for IETF Protocols
    //
    //      RFC 5116 - An Interface and Algorithms for Authenticated Encryption
    //
    //      RFC 8103 - Using ChaCha20-Poly1305 Authenticated Encryption in the
    //          Cryptographic Message Syntax (CMS)
    //
    //  Parameters:
    //
    //      Key Size - 32 bytes.
    //
    //      Nonce Size - 24 bytes.
    //
    //      Tag Size - 16 bytes.
    //
    //      Plaintext Size - Between 0 and 2^38-64 bytes. (A Span<byte> can only
    //          hold up to 2^31-1 bytes.)
    //
    //      Associated Data Size - Between 0 and 2^64-1 bytes.
    //
    //      Ciphertext Size - The ciphertext always has the size of the
    //          plaintext plus the tag size.
    //
    public sealed class XChaCha20Poly1305 : AeadAlgorithm
    {
        private static readonly NSecKeyFormatter s_nsecKeyFormatter = new NSecKeyFormatter(crypto_aead_chacha20poly1305_ietf_KEYBYTES, new byte[] { 0xDE, 0x31, 0x43, 0xDE });

        private static readonly Asn1Oid s_oid = new Asn1Oid(1, 2, 840, 113549, 1, 9, 16, 3, 18);

        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter(crypto_aead_chacha20poly1305_ietf_KEYBYTES);

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public XChaCha20Poly1305() : base(
            keySize: crypto_aead_chacha20poly1305_ietf_KEYBYTES,
            nonceSize: crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
            tagSize: crypto_aead_chacha20poly1305_ietf_ABYTES,
            maxPlaintextSize: int.MaxValue - crypto_aead_chacha20poly1305_ietf_ABYTES)
        {
            if (!s_selfTest.Value)
            {
                throw Error.Cryptographic_InitializationFailed(9293.ToString("X"));
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(seed.Length == crypto_aead_chacha20poly1305_ietf_KEYBYTES);

            publicKeyBytes = null;
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
            Debug.Assert(keyHandle.Length == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_chacha20poly1305_ietf_ABYTES);

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

        internal override int GetDefaultSeedSize()
        {
            return crypto_aead_chacha20poly1305_ietf_KEYBYTES;
        }

        private protected override bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_chacha20poly1305_ietf_ABYTES);

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
                return s_rawKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryExport(keyHandle, blob, out blobSize);
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
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryReadAlgorithmIdentifier(
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> nonce)
        {
            bool success = true;
            reader.BeginSequence();
            success &= reader.ObjectIdentifier().SequenceEqual(s_oid.Bytes);
            nonce = reader.OctetString();
            success &= (nonce.Length == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            reader.End();
            success &= reader.Success;
            return success;
        }

        internal override void WriteAlgorithmIdentifier(
            ref Asn1Writer writer,
            ReadOnlySpan<byte> nonce)
        {
            writer.End();
            writer.OctetString(nonce);
            writer.ObjectIdentifier(s_oid.Bytes);
            writer.BeginSequence();
        }

        private static bool SelfTest()
        {
            return (crypto_aead_chacha20poly1305_ietf_abytes() == (UIntPtr)crypto_aead_chacha20poly1305_ietf_ABYTES)
                && (crypto_aead_chacha20poly1305_ietf_keybytes() == (UIntPtr)crypto_aead_chacha20poly1305_ietf_KEYBYTES)
                && (crypto_aead_xchacha20poly1305_ietf_npubbytes() == (UIntPtr)crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
                && (crypto_aead_chacha20poly1305_ietf_nsecbytes() == (UIntPtr)crypto_aead_chacha20poly1305_ietf_NSECBYTES);
        }
    }
}
