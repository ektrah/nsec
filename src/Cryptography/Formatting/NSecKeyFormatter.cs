using System;
using System.Buffers.Binary;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class NSecKeyFormatter
    {
        private readonly uint _blobHeader;

        public NSecKeyFormatter(
            uint blobHeader)
        {
            _blobHeader = blobHeader;
        }

        public bool TryExport(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            Debug.Assert(keyHandle != null);

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
            int keySize,
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle)
        {
            int length = blob.Length - (sizeof(uint) + sizeof(uint));

            if (length != keySize ||
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
