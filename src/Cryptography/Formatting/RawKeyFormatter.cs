using System;
using System.Buffers;

namespace NSec.Cryptography.Formatting
{
    internal static class RawKeyFormatter
    {
        public static bool TryExport(
            ReadOnlySpan<byte> key,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = key.Length;

            if (blob.Length < blobSize)
            {
                return false;
            }

            key.CopyTo(blob);
            return true;
        }

        public static bool TryImport(
            int keySize,
            ReadOnlySpan<byte> blob,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte>? owner)
        {
            if (blob.Length != keySize)
            {
                memory = default;
                owner = default;
                return false;
            }

            owner = memoryPool.Rent(keySize);
            memory = owner.Memory.Slice(0, keySize);
            blob.CopyTo(owner.Memory.Span);
            return true;
        }
    }
}
