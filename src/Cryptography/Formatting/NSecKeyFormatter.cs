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

        public bool TryExport(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length >= _minKeySize);
            Debug.Assert(keyHandle.Length <= _maxKeySize);

            blobSize = _blobHeader.Length + sizeof(uint) + keyHandle.Length;

            if (blob.Length < blobSize)
            {
                return false;
            }

            _blobHeader.CopyTo(blob);
            blob.Slice(_blobHeader.Length).WriteLittleEndian((uint)keyHandle.Length);
            keyHandle.Export(blob.Slice(_blobHeader.Length + sizeof(uint)));
            return true;
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            int keySize = blob.Length - (_blobHeader.Length + sizeof(uint));

            if (keySize < _minKeySize ||
                keySize > _maxKeySize ||
                !blob.Slice(0, _blobHeader.Length).SequenceEqual(_blobHeader) ||
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
