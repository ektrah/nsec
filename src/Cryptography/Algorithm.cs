using System;
using System.Buffers;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography
{
    public abstract class Algorithm
    {
        private protected Algorithm()
        {
            Sodium.Initialize();
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool Equals(
            object? objA,
            object? objB)
        {
            return object.Equals(objA, objB);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool ReferenceEquals(
            object? objA,
            object? objB)
        {
            return object.ReferenceEquals(objA, objB);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public sealed override bool Equals(
            object? obj)
        {
            return this == obj;
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public sealed override int GetHashCode()
        {
            return RuntimeHelpers.GetHashCode(this);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public sealed override string? ToString()
        {
            return GetType().ToString();
        }

        // Creates a new libsodium secret key from a seed.
        internal virtual void CreateKey(
            ReadOnlySpan<byte> seed,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey? publicKey)
        {
            throw Error.NotSupported_CreateKey();
        }

        // Gets the secret key size.
        internal virtual int GetKeySize()
        {
            throw Error.NotSupported_CreateKey();
        }

        // Gets the public key size.
        internal virtual int GetPublicKeySize()
        {
            throw Error.NotSupported_CreateKey();
        }

        // Gets the seed size for creating a libsodium key.
        internal virtual int GetSeedSize()
        {
            throw Error.NotSupported_CreateKey();
        }

        // Converts a libsodium secret key into a key blob.
        internal virtual bool TryExportKey(
            ReadOnlySpan<byte> key,
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
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte>? owner,
            out PublicKey? publicKey)
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
