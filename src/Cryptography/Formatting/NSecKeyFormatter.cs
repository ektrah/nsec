using System;
using System.Buffers.Binary;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal static class NSecKeyFormatter
    {
        public static bool TryExport(
            uint blobHeader,
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = sizeof(uint) + sizeof(int) + keyHandle.Length;

            if (blob.Length < blobSize)
            {
                return false;
            }

            BinaryPrimitives.WriteUInt32BigEndian(blob, blobHeader);
            BinaryPrimitives.WriteInt32LittleEndian(blob.Slice(sizeof(uint)), keyHandle.Length);
            keyHandle.Export(blob.Slice(sizeof(uint) + sizeof(int)));
            return true;
        }

        public static bool TryImport(
            uint blobHeader,
            int keySize,
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle)
        {
            if (blob.Length != sizeof(uint) + sizeof(int) + keySize ||
                BinaryPrimitives.ReadUInt32BigEndian(blob) != blobHeader ||
                BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(sizeof(uint))) != keySize)
            {
                keyHandle = null;
                return false;
            }

            SecureMemoryHandle.Import(blob.Slice(sizeof(uint) + sizeof(int)), out keyHandle);
            return true;
        }
    }
}
