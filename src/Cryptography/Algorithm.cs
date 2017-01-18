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
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            throw new NotSupportedException();
        }

        // Converts a libsodium secret key into a key blob.
        internal virtual int ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob)
        {
            throw new NotSupportedException();
        }

        // Converts a libsodium public key into a key blob.
        internal virtual int ExportPublicKey(
            ReadOnlySpan<byte> publicKeyBytes,
            KeyBlobFormat format,
            Span<byte> blob)
        {
            throw new NotSupportedException();
        }

        // Gets the size for a derived key, if supported.
        internal virtual int GetDerivedKeySize()
        {
            throw new NotSupportedException();
        }

        // Gets the size of a key blob in the specified format.
        internal virtual int? GetKeyBlobSize(
            KeyBlobFormat format)
        {
            return null;
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
            throw new NotSupportedException();
        }

        // Converts a key blob into a libsodium public key.
        internal virtual bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out byte[] result)
        {
            throw new NotSupportedException();
        }
    }
}
