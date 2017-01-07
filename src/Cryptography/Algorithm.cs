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
        internal virtual SecureMemoryHandle CreateKey(
            out PublicKey publicKey)
        {
            throw new NotSupportedException();
        }

        // Gets the size for a derived key, if supported.
        internal virtual int GetDerivedKeySize()
        {
            throw new NotSupportedException();
        }

        // Converts a libsodium secret key into a key blob.
        internal virtual bool TryExportKey(
            Key key,
            KeyBlobFormat format,
            out byte[] result)
        {
            throw new NotSupportedException();
        }

        // Converts a libsodium public key into a key blob.
        internal virtual bool TryExportPublicKey(
            PublicKey publicKey,
            KeyBlobFormat format,
            out byte[] result)
        {
            throw new NotSupportedException();
        }

        // Converts a key blob into a libsodium secret key.
        internal virtual bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            KeyFlags flags,
            out Key result)
        {
            throw new NotSupportedException();
        }

        // Converts a key blob into a libsodium public key.
        internal virtual bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey result)
        {
            throw new NotSupportedException();
        }
    }
}
