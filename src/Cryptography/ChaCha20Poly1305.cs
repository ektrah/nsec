using System;
using System.Diagnostics;
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
        private static readonly KeyFormatter s_nsecKeyFormatter = new KeyFormatter(crypto_aead_chacha20poly1305_ietf_KEYBYTES, new byte[] { 0x7F, 0x31, 0x43, crypto_aead_chacha20poly1305_ietf_KEYBYTES });
        private static readonly Oid s_oid = new Oid(1, 2, 840, 113549, 1, 9, 16, 3, 18);
        private static readonly KeyFormatter s_rawKeyFormatter = new KeyFormatter(crypto_aead_chacha20poly1305_ietf_KEYBYTES, new byte[] { });
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public ChaCha20Poly1305() : base(
            keySize: crypto_aead_chacha20poly1305_ietf_KEYBYTES,
            nonceSize: crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
            tagSize: crypto_aead_chacha20poly1305_ietf_ABYTES)
        {
            if (!s_selfTest.Value)
                throw Error.Cryptographic_InitializationFailed();
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(seed.Length == crypto_aead_chacha20poly1305_ietf_KEYBYTES);

            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(seed.Length, out keyHandle);
            keyHandle.Import(seed);
        }

        internal override void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_chacha20poly1305_ietf_ABYTES);

            crypto_aead_chacha20poly1305_ietf_encrypt(
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

        internal override byte[] ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format)
        {
            Debug.Assert(keyHandle != null);

            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.Export(keyHandle);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.Export(keyHandle);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_aead_chacha20poly1305_ietf_KEYBYTES;
        }

        internal override bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_chacha20poly1305_ietf_ABYTES);

            int error = crypto_aead_chacha20poly1305_ietf_decrypt(
                ref plaintext.DangerousGetPinnableReference(),
                out ulong plaintextLength,
                IntPtr.Zero,
                ref ciphertext.DangerousGetPinnableReference(),
                (ulong)ciphertext.Length,
                ref associatedData.DangerousGetPinnableReference(),
                (ulong)associatedData.Length,
                ref nonce.DangerousGetPinnableReference(),
                keyHandle);

            // libsodium clears the plaintext if decryption fails.

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
            success &= (nonce.Length == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
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
                && (crypto_aead_chacha20poly1305_ietf_npubbytes() == (UIntPtr)crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
                && (crypto_aead_chacha20poly1305_ietf_nsecbytes() == (UIntPtr)crypto_aead_chacha20poly1305_ietf_NSECBYTES);
        }
    }
}
