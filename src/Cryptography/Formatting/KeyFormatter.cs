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

        public int BlobSize => _blobSize;

        public bool IsValid(
            ReadOnlySpan<byte> blob)
        {
            return blob.Length == _blobSize
                && blob.Slice(0, _blobHeader.Length).SequenceEqual(_blobHeader);
        }

        public bool TryExport(
            SecureMemoryHandle keyHandle,
            out byte[] result)
        {
            Debug.Assert(keyHandle != null);

            result = new byte[_blobSize];
            Buffer.BlockCopy(_blobHeader, 0, result, 0, _blobHeader.Length);
            Serialize(keyHandle, new Span<byte>(result, _blobHeader.Length));
            return true;
        }

        public bool TryExportText(
            SecureMemoryHandle keyHandle,
            out byte[] result)
        {
            Debug.Assert(keyHandle != null);

            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[_blobSize];
                    temp = new Span<byte>(pointer, _blobSize);
                }

                new ReadOnlySpan<byte>(_blobHeader).CopyTo(temp);
                Serialize(keyHandle, temp.Slice(_blobHeader.Length));
                result = Armor.Encode(temp, s_beginLabel, s_endLabel);
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
            if (!IsValid(blob))
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
            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[_blobSize];
                    temp = new Span<byte>(pointer, _blobSize);
                }

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
            Debug.Assert(span.Length == _blobSize - _blobHeader.Length);

            publicKeyBytes = null;
            SecureMemoryHandle.Alloc(span.Length, out keyHandle);
            keyHandle.Import(span);
        }

        protected virtual void Serialize(
            SecureMemoryHandle keyHandle,
            Span<byte> span)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == _blobSize - _blobHeader.Length);
            Debug.Assert(span.Length == _blobSize - _blobHeader.Length);

            keyHandle.Export(span);
        }
    }
}
