using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;
using static NSec.Cryptography.Experimental.Norx.Norx3241;

namespace NSec.Cryptography.Experimental
{
    //
    //  NORX32-4-1
    //
    //  References:
    //
    //      NORX v3.0 <https://norx.io/data/norx.pdf>
    //
    //  Parameters:
    //
    //      Key Size - 16 bytes.
    //
    //      Nonce Size - 16 bytes.
    //
    //      Tag Size - 16 bytes.
    //
    //      Plaintext Size - TODO.
    //
    //      Associated Data Size - TODO.
    //
    //      Ciphertext Size - The ciphertext always has the size of the
    //          plaintext plus the tag size.
    //
    public sealed class Norx3241 : AeadAlgorithm
    {
        private static readonly RawKeyFormatter s_rawKeyFormatter = new RawKeyFormatter(crypto_aead_norx3241_KEYBYTES);

        public Norx3241() : base(
            keySize: crypto_aead_norx3241_KEYBYTES,
            nonceSize: crypto_aead_norx3241_NPUBBYTES,
            tagSize: crypto_aead_norx3241_ABYTES,
            maxPlaintextSize: 123456) // TODO: Norx3241.maxPlaintextSize
        {
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(seed.Length == crypto_aead_norx3241_KEYBYTES);

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
            Debug.Assert(keyHandle.Length == crypto_aead_norx3241_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_norx3241_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_norx3241_ABYTES);

            crypto_aead_norx3241_encrypt(
                ref MemoryMarshal.GetReference(ciphertext),
                out ulong ciphertextLength,
                ref MemoryMarshal.GetReference(plaintext),
                (ulong)plaintext.Length,
                ref MemoryMarshal.GetReference(associatedData),
                (ulong)associatedData.Length,
                IntPtr.Zero,
                ref Unsafe.As<Nonce, byte>(ref Unsafe.AsRef(in nonce)),
                keyHandle);

            Debug.Assert((ulong)ciphertext.Length == ciphertextLength);
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_aead_norx3241_KEYBYTES;
        }

        private protected override bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_norx3241_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_aead_norx3241_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_norx3241_ABYTES);

            int error = crypto_aead_norx3241_decrypt(
                ref MemoryMarshal.GetReference(plaintext),
                out ulong plaintextLength,
                IntPtr.Zero,
                ref MemoryMarshal.GetReference(ciphertext),
                (ulong)ciphertext.Length,
                ref MemoryMarshal.GetReference(associatedData),
                (ulong)associatedData.Length,
                ref Unsafe.As<Nonce, byte>(ref Unsafe.AsRef(in nonce)),
                keyHandle);

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
            case KeyBlobFormat.NSecSymmetricKey: // TODO: Norx NSecSymmetricKey format
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
            case KeyBlobFormat.NSecSymmetricKey: // TODO: Norx NSecSymmetricKey format
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryReadAlgorithmIdentifier(
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> nonce)
        {
            throw new NotImplementedException();
        }

        internal override void WriteAlgorithmIdentifier(
            ref Asn1Writer writer,
            ReadOnlySpan<byte> nonce)
        {
            throw new NotImplementedException();
        }
    }
}
