using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public abstract class Algorithm
    {
        internal Algorithm()
        {
            Sodium.Initialize();
        }

        // Allocates a new, initialized libsodium secret key.
        internal virtual void CreateKey(
            SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            throw Error.NotSupported_CreateKey();
        }

        // Converts a libsodium secret key into a key blob.
        internal virtual int ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob)
        {
            throw Error.NotSupported_ExportKey();
        }

        // Converts a libsodium public key into a key blob.
        internal virtual int ExportPublicKey(
            ReadOnlySpan<byte> publicKeyBytes,
            KeyBlobFormat format,
            Span<byte> blob)
        {
            throw Error.NotSupported_ExportKey();
        }

        // Gets the default size for a libsodium secret key, if supported.
        internal virtual int GetDefaultKeySize()
        {
            throw Error.NotSupported_CreateKey();
        }

        // Gets the size of a key blob in the specified format.
        internal virtual int GetKeyBlobSize(
            KeyBlobFormat format)
        {
            throw Error.NotSupported_ExportKey();
        }

        // Gets the supported key blob formats.
        internal virtual ReadOnlySpan<KeyBlobFormat> GetSupportedKeyBlobFormats()
        {
            return ReadOnlySpan<KeyBlobFormat>.Empty;
        }

        // Converts a key blob into a libsodium secret key.
        internal virtual bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            throw Error.NotSupported_ImportKey();
        }

        // Converts a key blob into a libsodium public key.
        internal virtual bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out byte[] result)
        {
            throw Error.NotSupported_ImportKey();
        }
    }
}
