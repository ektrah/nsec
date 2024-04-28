using System;
using System.Buffers.Binary;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal static class NSecKeyFormatter
    {
        public static bool TryExport(
            uint blobHeader,
            int keySize,
            int outputSize,
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            Debug.Assert(keyHandle.Size == keySize);

            blobSize = sizeof(uint) + sizeof(short) + sizeof(short) + keySize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            BinaryPrimitives.WriteUInt32BigEndian(blob, blobHeader);
            BinaryPrimitives.WriteInt16LittleEndian(blob[sizeof(uint)..], (short)keySize);
            BinaryPrimitives.WriteInt16LittleEndian(blob[(sizeof(uint) + sizeof(short))..], (short)outputSize);
            keyHandle.CopyTo(blob.Slice(sizeof(uint) + sizeof(short) + sizeof(short), keySize));
            return true;
        }

        public static bool TryImport(
            uint blobHeader,
            int keySize,
            int outputSize,
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle? keyHandle)
        {
            if (blob.Length != sizeof(uint) + sizeof(short) + sizeof(short) + keySize ||
                BinaryPrimitives.ReadUInt32BigEndian(blob) != blobHeader ||
                BinaryPrimitives.ReadInt16LittleEndian(blob[sizeof(uint)..]) != keySize ||
                BinaryPrimitives.ReadInt16LittleEndian(blob[(sizeof(uint) + sizeof(short))..]) != outputSize)
            {
                keyHandle = default;
                return false;
            }

            keyHandle = SecureMemoryHandle.CreateFrom(blob.Slice(sizeof(uint) + sizeof(short) + sizeof(short), keySize));
            return true;
        }
    }
}
