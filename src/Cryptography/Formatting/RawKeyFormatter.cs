using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal sealed class RawKeyFormatter
    {
        public RawKeyFormatter()
        {
        }

        public bool TryExport(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            Debug.Assert(keyHandle != null);

            blobSize = keyHandle.Length;

            if (blob.Length < blobSize)
            {
                return false;
            }

            keyHandle.Export(blob);
            return true;
        }

        public bool TryImport(
            int keySize,
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle)
        {
            if (blob.Length < keySize || blob.Length > keySize)
            {
                keyHandle = null;
                return false;
            }

            SecureMemoryHandle.Import(blob, out keyHandle);
            return true;
        }
    }
}
