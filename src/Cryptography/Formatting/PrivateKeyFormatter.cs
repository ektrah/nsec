using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal class PrivateKeyFormatter
    {
        private static readonly byte[] s_beginLabel =
        {
            // "-----BEGIN PRIVATE KEY-----"
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47,
            0x49, 0x4E, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41,
            0x54, 0x45, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D,
            0x2D, 0x2D, 0x2D,
        };

        private static readonly byte[] s_endLabel =
        {
            // "-----END PRIVATE KEY-----"
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44,
            0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45,
            0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D,
            0x2D,
        };

        private readonly byte[] _blobHeader;
        private readonly int _blobSize;
        private readonly int _blobTextSize;
        private readonly int _keySize;

        public PrivateKeyFormatter(
            int keySize,
            byte[] blobHeader)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(blobHeader != null);

            _keySize = keySize;
            _blobHeader = blobHeader;
            _blobSize = blobHeader.Length + keySize;
            _blobTextSize = Armor.GetEncodedLength(_blobSize, s_beginLabel, s_endLabel);
        }

        public bool TryExport(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            Debug.Assert(keyHandle != null);

            blobSize = _blobSize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            _blobHeader.CopyTo(blob);
            Serialize(keyHandle, blob.Slice(_blobHeader.Length));
            return true;
        }

        public bool TryExportText(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            Debug.Assert(keyHandle != null);

            blobSize = _blobTextSize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            Span<byte> temp = stackalloc byte[_blobSize];
            try
            {
                _blobHeader.CopyTo(temp);
                Serialize(keyHandle, temp.Slice(_blobHeader.Length));

                Armor.Encode(temp, s_beginLabel, s_endLabel, blob);
                return true;
            }
            finally
            {
                sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
            }
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            if (blob.Length != _blobSize || !blob.StartsWith(_blobHeader))
            {
                keyHandle = null;
                publicKeyBytes = null;
                return false;
            }

            Deserialize(blob.Slice(_blobHeader.Length), out keyHandle, out publicKeyBytes);
            return true;
        }

        public bool TryImportText(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Span<byte> temp = stackalloc byte[_blobSize];
            try
            {
                if (!Armor.TryDecode(blob, s_beginLabel, s_endLabel, temp))
                {
                    keyHandle = null;
                    publicKeyBytes = null;
                    return false;
                }

                return TryImport(temp, out keyHandle, out publicKeyBytes);
            }
            finally
            {
                sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
            }
        }

        protected virtual void Deserialize(
            ReadOnlySpan<byte> span,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(span.Length == _keySize);

            publicKeyBytes = null;
            SecureMemoryHandle.Import(span, out keyHandle);
        }

        protected virtual void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == _keySize);
            Debug.Assert(span.Length == _keySize);

            keyHandle.Export(span);
        }
    }
}
