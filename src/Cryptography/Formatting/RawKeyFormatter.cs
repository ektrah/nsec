using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal class RawKeyFormatter
    {
        private readonly int _maxKeySize;
        private readonly int _minKeySize;

        public RawKeyFormatter(
            int minKeySize,
            int maxKeySize)
        {
            Debug.Assert(minKeySize >= 0);
            Debug.Assert(maxKeySize >= minKeySize);

            _minKeySize = minKeySize;
            _maxKeySize = maxKeySize;
        }

        public bool TryExport(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length >= _minKeySize);
            Debug.Assert(keyHandle.Length <= _maxKeySize);

            blobSize = keyHandle.Length;

            if (blob.Length < blobSize)
            {
                return false;
            }

            keyHandle.Export(blob);
            return true;
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            int keySize = blob.Length;

            if (keySize < _minKeySize || keySize > _maxKeySize)
            {
                keyHandle = null;
                publicKeyBytes = null;
                return false;
            }

            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(keySize, out keyHandle);
            keyHandle.Import(blob);
            return true;
        }
    }
}
