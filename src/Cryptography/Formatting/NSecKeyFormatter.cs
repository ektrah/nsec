using System;
using System.Buffers.Binary;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class NSecKeyFormatter
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
            BinaryPrimitives.WriteUInt32LittleEndian(blob.Slice(_blobHeader.Length), (uint)keyHandle.Length);
            keyHandle.Export(blob.Slice(_blobHeader.Length + sizeof(uint)));
            return true;
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            int start = _blobHeader.Length + sizeof(uint);
            int length = blob.Length - start;

            if (length < _minKeySize ||
                length > _maxKeySize ||
                !blob.Slice(0, _blobHeader.Length).SequenceEqual(_blobHeader) ||
                BinaryPrimitives.ReadUInt32LittleEndian(blob.Slice(_blobHeader.Length, sizeof(uint))) != (uint)length)
            {
                keyHandle = null;
                publicKeyBytes = null;
                return false;
            }

            publicKeyBytes = null;
            SecureMemoryHandle.Import(blob.Slice(start, length), out keyHandle);
            return true;
        }
    }
}
