using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;

namespace NSec.Cryptography.Formatting
{
    internal static class NSecKeyFormatter
    {
        public static bool TryExport(
            uint blobHeader,
            int keySize,
            int outputSize,
            ReadOnlySpan<byte> key,
            Span<byte> blob,
            out int blobSize)
        {
            Debug.Assert(key.Length == keySize);

            blobSize = sizeof(uint) + sizeof(short) + sizeof(short) + keySize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            BinaryPrimitives.WriteUInt32BigEndian(blob, blobHeader);
            BinaryPrimitives.WriteInt16LittleEndian(blob.Slice(sizeof(uint)), (short)keySize);
            BinaryPrimitives.WriteInt16LittleEndian(blob.Slice(sizeof(uint) + sizeof(short)), (short)outputSize);
            key.CopyTo(blob.Slice(sizeof(uint) + sizeof(short) + sizeof(short), keySize));
            return true;
        }

        public static bool TryImport(
            uint blobHeader,
            int keySize,
            int outputSize,
            ReadOnlySpan<byte> blob,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte>? owner)
        {
            if (blob.Length != sizeof(uint) + sizeof(short) + sizeof(short) + keySize ||
                BinaryPrimitives.ReadUInt32BigEndian(blob) != blobHeader ||
                BinaryPrimitives.ReadInt16LittleEndian(blob.Slice(sizeof(uint))) != keySize ||
                BinaryPrimitives.ReadInt16LittleEndian(blob.Slice(sizeof(uint) + sizeof(short))) != outputSize)
            {
                memory = default;
                owner = default;
                return false;
            }

            owner = memoryPool.Rent(keySize);
            memory = owner.Memory.Slice(0, keySize);
            blob.Slice(sizeof(uint) + sizeof(short) + sizeof(short), keySize).CopyTo(owner.Memory.Span);
            return true;
        }
    }
}
