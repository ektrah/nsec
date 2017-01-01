using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal class KeyFormatter
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

        public KeyFormatter(
            int keySize,
            byte[] blobHeader)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(blobHeader != null);

            _blobSize = blobHeader.Length + keySize;
            _blobHeader = blobHeader;
        }

        public bool TryExport(
            Key key,
            out byte[] result)
        {
            Debug.Assert(key != null);

            byte[] blob = new byte[_blobSize];
            Buffer.BlockCopy(_blobHeader, 0, blob, 0, _blobHeader.Length);
            Serialize(key, new Span<byte>(blob, _blobHeader.Length));
            result = blob;
            return true;
        }

        public bool TryExportText(
            Key key,
            out byte[] result)
        {
            Debug.Assert(key != null);

            byte[] temp = new byte[_blobSize]; // TODO: avoid placing sensitive data in managed memory
            new ReadOnlySpan<byte>(_blobHeader).CopyTo(temp);
            Serialize(key, new Span<byte>(temp, _blobHeader.Length));
            result = Armor.Encode(temp, s_beginLabel, s_endLabel);
            return true;
        }

        public bool TryImport(
            Algorithm algorithm,
            KeyFlags flags,
            ReadOnlySpan<byte> blob,
            out Key result)
        {
            Debug.Assert(algorithm != null);

            if (blob.Length != _blobSize || !blob.Slice(0, _blobHeader.Length).BlockEquals(_blobHeader))
            {
                result = null;
                return false;
            }

            result = Deserialize(algorithm, flags, blob.Slice(_blobHeader.Length));
            return true;
        }

        public bool TryImportText(
            Algorithm algorithm,
            KeyFlags flags,
            ReadOnlySpan<byte> blob,
            out Key result)
        {
            Debug.Assert(algorithm != null);

            byte[] temp = new byte[_blobSize]; // TODO: avoid placing sensitive data in managed memory

            if (!Armor.TryDecode(blob, s_beginLabel, s_endLabel, temp))
            {
                result = null;
                return false;
            }

            return TryImport(algorithm, flags, temp, out result);
        }

        protected virtual Key Deserialize(
            Algorithm algorithm,
            KeyFlags flags,
            ReadOnlySpan<byte> span)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(span.Length == _blobSize - _blobHeader.Length);

            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(span.Length);
            handle.Import(span);
            return new Key(algorithm, flags, handle, null);
        }

        protected virtual void Serialize(
            Key key,
            Span<byte> span)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.Handle.Length == _blobSize - _blobHeader.Length);
            Debug.Assert(span.Length == _blobSize - _blobHeader.Length);

            key.Handle.Export(span);
        }
    }
}
