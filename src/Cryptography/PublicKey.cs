using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Algorithm = {Algorithm}")]
    public sealed class PublicKey : IEquatable<PublicKey>
    {
        private readonly Algorithm _algorithm;

        private PublicKeyBytes _bytes;

        internal PublicKey(
            Algorithm algorithm)
        {
            _algorithm = algorithm;
        }

        public Algorithm Algorithm => _algorithm;

        public int Size => _algorithm.GetPublicKeySize();

        public static PublicKey Import(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            if (!algorithm.TryImportPublicKey(blob, format, out PublicKey publicKey))
            {
                throw Error.Format_InvalidBlob();
            }

            return publicKey;
        }

        public static bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey? result)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            if (!algorithm.TryImportPublicKey(blob, format, out PublicKey publicKey))
            {
                result = null;
                return false;
            }

            result = publicKey;
            return true;
        }

        public bool Equals(
            PublicKey? other)
        {
            if (other == this)
            {
                return true;
            }
            if (other == null || other._algorithm != _algorithm)
            {
                return false;
            }

            ReadOnlySpan<byte> bytes = _bytes;
            return bytes.SequenceEqual(other._bytes);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(
            object? obj)
        {
            return Equals(obj as PublicKey);
        }

        public byte[] Export(
            KeyBlobFormat format)
        {
            _algorithm.TryExportPublicKey(this, format, [], out int blobSize);
            byte[] blob = new byte[blobSize];

            if (!_algorithm.TryExportPublicKey(this, format, blob, out blobSize))
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(blobSize == blob.Length);
            return blob;
        }

        public int GetExportBlobSize(
            KeyBlobFormat format)
        {
            _algorithm.TryExportPublicKey(this, format, [], out int blobSize);
            return blobSize;
        }

        public override int GetHashCode()
        {
            ReadOnlySpan<uint> values = MemoryMarshal.Cast<byte, uint>(_bytes);
            return HashCode.Combine(values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7]);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString()
        {
            return typeof(PublicKey).ToString();
        }

        public bool TryExport(
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            return _algorithm.TryExportPublicKey(this, format, blob, out blobSize);
        }

        internal ref PublicKeyBytes GetPinnableReference()
        {
            return ref _bytes;
        }
    }
}
