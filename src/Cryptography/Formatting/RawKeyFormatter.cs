using System;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal static class RawKeyFormatter
    {
        public static bool TryExport(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = keyHandle.Size;

            if (blob.Length < blobSize)
            {
                return false;
            }

            keyHandle.CopyTo(blob);
            return true;
        }

        public static bool TryImport(
            int keySize,
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle? keyHandle)
        {
            if (blob.Length != keySize)
            {
                keyHandle = default;
                return false;
            }

            keyHandle = SecureMemoryHandle.CreateFrom(blob);
            return true;
        }
    }
}
