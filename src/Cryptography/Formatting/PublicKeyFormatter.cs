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
            _blobTextSize = Armor.GetEncodedSize(_blobSize, s_beginLabel, s_endLabel);
        }

        public int BlobSize => _blobSize;

        public int BlobTextSize => _blobTextSize;

        public byte[] Export(
            ReadOnlySpan<byte> publicKeyBytes)
        {
            byte[] blob = new byte[_blobSize];
            new ReadOnlySpan<byte>(_blobHeader).CopyTo(blob);
            Serialize(publicKeyBytes, new Span<byte>(blob, _blobHeader.Length, _keySize));
            return blob;
        }

        public byte[] ExportText(
            ReadOnlySpan<byte> publicKeyBytes)
        {
            byte[] temp = new byte[_blobSize];
            new ReadOnlySpan<byte>(_blobHeader).CopyTo(temp);
            Serialize(publicKeyBytes, new Span<byte>(temp, _blobHeader.Length));

            byte[] blob = new byte[_blobTextSize];
            Armor.Encode(temp, s_beginLabel, s_endLabel, new Span<byte>(blob, 0, _blobTextSize));
            return blob;
        }

        public bool IsValid(
            ReadOnlySpan<byte> blob)
        {
            return blob.Length == _blobSize && blob.StartsWith(_blobHeader);
        }

        public bool TryImport(
            ReadOnlySpan<byte> blob,
            out byte[] result)
        {
            if (!IsValid(blob))
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
            byte[] temp = new byte[_blobSize];

            if (!Armor.TryDecode(blob, s_beginLabel, s_endLabel, temp))
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
