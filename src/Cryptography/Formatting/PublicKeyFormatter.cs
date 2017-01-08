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

        public PublicKeyFormatter(
            int keySize,
            byte[] blobHeader)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(blobHeader != null);

            _blobSize = blobHeader.Length + keySize;
            _blobHeader = blobHeader;
        }

        public bool TryExport(
            ReadOnlySpan<byte> publicKeyBytes,
            out byte[] result)
        {
            byte[] blob = new byte[_blobSize];
            Buffer.BlockCopy(_blobHeader, 0, blob, 0, _blobHeader.Length);
            Serialize(publicKeyBytes, new Span<byte>(blob, _blobHeader.Length));
            result = blob;
            return true;
        }

        public bool TryExportText(
            ReadOnlySpan<byte> publicKeyBytes,
            out byte[] result)
        {
            byte[] blob = new byte[_blobSize];
            new ReadOnlySpan<byte>(_blobHeader).CopyTo(blob);
            Serialize(publicKeyBytes, new Span<byte>(blob, _blobHeader.Length));
            result = Armor.Encode(blob, s_beginLabel, s_endLabel);
            return true;
        }

        public bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            out PublicKey result)
        {
            Debug.Assert(algorithm != null);

            if (blob.Length != _blobSize || !blob.Slice(0, _blobHeader.Length).BlockEquals(_blobHeader))
            {
                result = null;
                return false;
            }

            result = Deserialize(algorithm, blob.Slice(_blobHeader.Length));
            return true;
        }

        public bool TryImportText(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            out PublicKey result)
        {
            Debug.Assert(algorithm != null);

            byte[] temp = new byte[_blobSize];

            if (!Armor.TryDecode(blob, s_beginLabel, s_endLabel, temp))
            {
                result = null;
                return false;
            }

            return TryImport(algorithm, temp, out result);
        }

        protected virtual PublicKey Deserialize(
            Algorithm algorithm,
            ReadOnlySpan<byte> span)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(span.Length == _blobSize - _blobHeader.Length);

            return new PublicKey(algorithm, span.ToArray());
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
