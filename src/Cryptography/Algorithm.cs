using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public abstract class Algorithm
    {
        private protected Algorithm()
        {
            Sodium.Initialize();
        }

        // Creates a new libsodium secret key from a seed.
        internal virtual void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out PublicKey publicKey)
        {
            throw Error.NotSupported_CreateKey();
        }

        // Gets the default seed size for creating a libsodium key.
        internal virtual int GetDefaultSeedSize()
        {
            throw Error.NotSupported_CreateKey();
        }

        // Converts a libsodium secret key into a key blob.
        internal virtual bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            throw Error.NotSupported_ExportKey();
        }

        // Converts a libsodium public key into a key blob.
        internal virtual bool TryExportPublicKey(
            PublicKey publicKey,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            throw Error.NotSupported_ExportKey();
        }

        // Converts a key blob into a libsodium secret key.
        internal virtual bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out PublicKey publicKey)
        {
            throw Error.NotSupported_ImportKey();
        }

        // Converts a key blob into a libsodium public key.
        internal virtual bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey publicKey)
        {
            throw Error.NotSupported_ImportKey();
        }
    }
}
