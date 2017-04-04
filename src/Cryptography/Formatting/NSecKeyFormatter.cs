using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal class NSecKeyFormatter
    {
        private readonly byte[] _blobHeader;
        private readonly int _maxKeySize;
        private readonly int _minKeySize;

        public NSecKeyFormatter(
            int minKeySize,
            int maxKeySize,
            byte[] blobHeader)
        {
            Debug.Assert(minKeySize >= 0);
            Debug.Assert(maxKeySize >= minKeySize);
            Debug.Assert(blobHeader != null);

            _minKeySize = minKeySize;
            _maxKeySize = maxKeySize;
            _blobHeader = blobHeader;
        }

        public byte[] Export(
            SecureMemoryHandle keyHandle)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length >= _minKeySize);
            Debug.Assert(keyHandle.Length <= _maxKeySize);

            byte[] blob = new byte[_blobHeader.Length + sizeof(uint) + keyHandle.Length];
            _blobHeader.CopyTo(blob);
            blob.AsSpan().Slice(_blobHeader.Length).WriteLittleEndian((uint)keyHandle.Length);
            keyHandle.Export(blob.AsSpan().Slice(_blobHeader.Length + sizeof(uint)));
            return blob;
        }

        public int GetBlobSize(
            int keySize)
        {
            return 8 + keySize;
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            int keySize = blob.Length - (_blobHeader.Length + sizeof(uint));

            if (keySize < _minKeySize ||
                keySize > _maxKeySize ||
                blob.Length < _blobHeader.Length + sizeof(uint) ||
                !blob.StartsWith(_blobHeader) ||
                blob.Slice(_blobHeader.Length).ReadLittleEndian() != (uint)keySize)
            {
                keyHandle = null;
                publicKeyBytes = null;
                return false;
            }

            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(keySize, out keyHandle);
            keyHandle.Import(blob.Slice(_blobHeader.Length + sizeof(uint)));
            return true;
        }
    }
}
