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
            blobSize = keyHandle.Length;

            if (blob.Length < blobSize)
            {
                return false;
            }

            keyHandle.Export(blob);
            return true;
        }

        public static bool TryImport(
            int keySize,
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle)
        {
            if (blob.Length != keySize)
            {
                keyHandle = null;
                return false;
            }

            SecureMemoryHandle.Import(blob, out keyHandle);
            return true;
        }
    }
}
