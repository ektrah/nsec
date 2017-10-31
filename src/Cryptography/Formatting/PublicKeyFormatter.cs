using System;
using System.Diagnostics;

namespace NSec.Cryptography.Formatting
{
    internal class PublicKeyFormatter
    {
        private static readonly byte[] s_beginLabel =
        {
            // "-----BEGIN PUBLIC KEY-----"
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47,
            0x49, 0x4E, 0x20, 0x50, 0x55, 0x42, 0x4C, 0x49,
            0x43, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D,
            0x2D, 0x2D,
        };

        private static readonly byte[] s_endLabel =
        {
            // "-----END PUBLIC KEY-----"
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44,
            0x20, 0x50, 0x55, 0x42, 0x4C, 0x49, 0x43, 0x20,
            0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D,
        };

        private readonly byte[] _blobHeader;
        private readonly int _blobSize;
        private readonly int _blobTextSize;
        private readonly int _keySize;

        public PublicKeyFormatter(
            int keySize,
            byte[] blobHeader)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(blobHeader != null);

            _keySize = keySize;
            _blobHeader = blobHeader;
            _blobSize = blobHeader.Length + keySize;
            _blobTextSize = Armor.GetEncodedToUtf8Length(_blobSize, s_beginLabel, s_endLabel);
        }

        public bool TryExport(
            ReadOnlySpan<byte> publicKeyBytes,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = _blobSize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            _blobHeader.CopyTo(blob);
            Serialize(publicKeyBytes, blob.Slice(_blobHeader.Length));
            return true;
        }

        public bool TryExportText(
            ReadOnlySpan<byte> publicKeyBytes,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = _blobTextSize;

            if (blob.Length < blobSize)
            {
                return false;
            }

            Span<byte> temp = stackalloc byte[_blobSize];

            _blobHeader.CopyTo(temp);
            Serialize(publicKeyBytes, temp.Slice(_blobHeader.Length));

            Armor.EncodeToUtf8(temp, s_beginLabel, s_endLabel, blob);
            return true;
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out byte[] result)
        {
            if (blob.Length != _blobSize || !blob.StartsWith(_blobHeader))
            {
                result = null;
                return false;
            }

            result = Deserialize(blob.Slice(_blobHeader.Length));
            return true;
        }

        public bool TryImportText(
            ReadOnlySpan<byte> blob,
            out byte[] result)
        {
            Span<byte> temp = stackalloc byte[_blobSize];

            if (!Armor.TryDecodeFromUtf8(blob, s_beginLabel, s_endLabel, temp, out int written) || written != _blobSize)
            {
                result = null;
                return false;
            }

            return TryImport(temp, out result);
        }

        protected virtual byte[] Deserialize(
            ReadOnlySpan<byte> span)
        {
            Debug.Assert(span.Length == _blobSize - _blobHeader.Length);

            return span.ToArray();
        }

        protected virtual void Serialize(
            ReadOnlySpan<byte> publicKeyBytes,
            Span<byte> span)
        {
            Debug.Assert(publicKeyBytes.Length == _blobSize - _blobHeader.Length);
            Debug.Assert(span.Length == _blobSize - _blobHeader.Length);

            publicKeyBytes.CopyTo(span);
        }
    }
}
