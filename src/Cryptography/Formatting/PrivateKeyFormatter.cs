using System;
using System.Buffers;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal abstract class PrivateKeyFormatter
    {
        private static readonly byte[] s_beginLabel =
        [
            // "-----BEGIN PRIVATE KEY-----"
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47,
            0x49, 0x4E, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41,
            0x54, 0x45, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D,
            0x2D, 0x2D, 0x2D,
        ];

        private static readonly byte[] s_endLabel =
        [
            // "-----END PRIVATE KEY-----"
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44,
            0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45,
            0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D,
            0x2D,
        ];

        private readonly byte[] _blobHeader;
        private readonly int _blobSize;
        private readonly int _blobTextSize;
        private readonly int _keySize;

        public PrivateKeyFormatter(
            int keySize,
            byte[] blobHeader)
        {
            Debug.Assert(keySize > 0);

            _keySize = keySize;
            _blobHeader = blobHeader;
            _blobSize = blobHeader.Length + keySize;
            _blobTextSize = Armor.GetEncodedToUtf8Length(_blobSize, s_beginLabel, s_endLabel);
        }

        public bool TryExport(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = _blobSize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            _blobHeader.CopyTo(blob);
            Serialize(keyHandle, blob.Slice(_blobHeader.Length, _keySize));
            return true;
        }

        public bool TryExportText(
            SecureMemoryHandle keyHandle,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = _blobTextSize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            Span<byte> temp = stackalloc byte[_blobSize];
            try
            {
                _blobHeader.CopyTo(temp);
                Serialize(keyHandle, temp[_blobHeader.Length..]);

                Armor.EncodeToUtf8(temp, s_beginLabel, s_endLabel, blob[.._blobTextSize]);
                return true;
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(temp);
            }
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle? keyHandle,
            out PublicKeyBytes publicKeyBytes)
        {
            if (blob.Length != _blobSize || !blob.StartsWith(_blobHeader))
            {
                keyHandle = default;
                publicKeyBytes = default;
                return false;
            }

            Deserialize(blob[_blobHeader.Length..], out keyHandle, out publicKeyBytes);
            return true;
        }

        public bool TryImportText(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle? keyHandle,
            out PublicKeyBytes publicKeyBytes)
        {
            Span<byte> temp = stackalloc byte[_blobSize];
            try
            {
                if (!Armor.TryDecodeFromUtf8(blob, s_beginLabel, s_endLabel, temp, out int written) || written != _blobSize)
                {
                    keyHandle = default;
                    publicKeyBytes = default;
                    return false;
                }

                return TryImport(temp, out keyHandle, out publicKeyBytes);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(temp);
            }
        }

        protected abstract void Deserialize(
            ReadOnlySpan<byte> span,
            out SecureMemoryHandle? keyHandle,
            out PublicKeyBytes publicKeyBytes);

        protected abstract void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span);
    }
}
