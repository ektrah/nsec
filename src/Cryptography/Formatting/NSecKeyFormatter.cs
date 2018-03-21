using System;
using System.Buffers.Binary;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class NSecKeyFormatter
    {
        private readonly uint _blobHeader;
        private readonly int _maxKeySize;
        private readonly int _minKeySize;

        public NSecKeyFormatter(
            int keySize,
            uint blobHeader)
        {
            Debug.Assert(keySize >= 0);

            _minKeySize = keySize;
            _maxKeySize = keySize;
            _blobHeader = blobHeader;
        }

        public NSecKeyFormatter(
            int minKeySize,
            int maxKeySize,
            uint blobHeader)
        {
            Debug.Assert(minKeySize >= 0);
            Debug.Assert(maxKeySize >= minKeySize);

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

            blobSize = sizeof(uint) + sizeof(uint) + keyHandle.Length;

            if (blob.Length < blobSize)
            {
                return false;
            }

            BinaryPrimitives.WriteUInt32BigEndian(blob, _blobHeader);
            BinaryPrimitives.WriteInt32LittleEndian(blob.Slice(sizeof(uint)), keyHandle.Length);
            keyHandle.Export(blob.Slice(sizeof(uint) + sizeof(uint)));
            return true;
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle)
        {
            int length = blob.Length - (sizeof(uint) + sizeof(uint));

            if (length < _minKeySize ||
                length > _maxKeySize ||
                BinaryPrimitives.ReadUInt32BigEndian(blob) != _blobHeader ||
                BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(sizeof(uint))) != length)
            {
                keyHandle = null;
                return false;
            }

            SecureMemoryHandle.Import(blob.Slice(sizeof(uint) + sizeof(uint), length), out keyHandle);
            return true;
        }
    }
}
