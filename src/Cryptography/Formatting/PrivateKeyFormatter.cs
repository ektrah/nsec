using System;
using System.Buffers;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal abstract class PrivateKeyFormatter
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

            _keySize = keySize;
            _blobHeader = blobHeader;
            _blobSize = blobHeader.Length + keySize;
            _blobTextSize = Armor.GetEncodedToUtf8Length(_blobSize, s_beginLabel, s_endLabel);
        }

        public bool TryExport(
            ReadOnlySpan<byte> privateKeyBytes,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = _blobSize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            _blobHeader.CopyTo(blob);
            Serialize(privateKeyBytes, blob.Slice(_blobHeader.Length, _keySize));
            return true;
        }

        public bool TryExportText(
            ReadOnlySpan<byte> privateKeyBytes,
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
                Serialize(privateKeyBytes, temp.Slice(_blobHeader.Length));

                Armor.EncodeToUtf8(temp, s_beginLabel, s_endLabel, blob.Slice(0, _blobTextSize));
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(temp);
            }
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte>? owner,
            out PublicKeyBytes publicKeyBytes)
        {
            if (blob.Length != _blobSize || !blob.StartsWith(_blobHeader))
            {
                memory = default;
                owner = default;
                publicKeyBytes = default;
                return false;
            }

            Deserialize(blob.Slice(_blobHeader.Length), memoryPool, out memory, out owner, out publicKeyBytes);
            return true;
        }

        public bool TryImportText(
            ReadOnlySpan<byte> blob,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte>? owner,
            out PublicKeyBytes publicKeyBytes)
        {
            Span<byte> temp = stackalloc byte[_blobSize];
            try
            {
                if (!Armor.TryDecodeFromUtf8(blob, s_beginLabel, s_endLabel, temp, out int written) || written != _blobSize)
                {
                    memory = default;
                    owner = default;
                    publicKeyBytes = default;
                    return false;
                }

                return TryImport(temp, memoryPool, out memory, out owner, out publicKeyBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(temp);
            }
        }

        protected abstract void Deserialize(
            ReadOnlySpan<byte> span,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKeyBytes publicKeyBytes);

        protected abstract void Serialize(
            ReadOnlySpan<byte> privateKeyBytes,
            Span<byte> span);
    }
}
