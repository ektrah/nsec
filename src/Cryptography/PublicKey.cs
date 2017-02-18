using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Algorithm = {Algorithm}")]
    public sealed class PublicKey : IEquatable<PublicKey>
    {
        private readonly Algorithm _algorithm;
        private readonly byte[] _bytes;

        internal PublicKey(
            Algorithm algorithm,
            byte[] bytes)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(bytes != null);

            _algorithm = algorithm;
            _bytes = bytes;
        }

        public Algorithm Algorithm => _algorithm;

        internal ReadOnlySpan<byte> Bytes => _bytes;

        public static PublicKey Import(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            if (!algorithm.TryImportPublicKey(blob, format, out byte[] publicKeyBytes))
            {
                throw new FormatException();
            }

            return new PublicKey(algorithm, publicKeyBytes);
        }

        public static bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey result)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            if (!algorithm.TryImportPublicKey(blob, format, out byte[] publicKeyBytes))
            {
                result = null;
                return false;
            }

            result = new PublicKey(algorithm, publicKeyBytes);
            return true;
        }

        public bool Equals(
            PublicKey other)
        {
            return (this == other)
                || (other != null)
                && (_algorithm.GetType() == other._algorithm.GetType())
                && SpanExtensions.SequenceEqual(_bytes, other._bytes);
        }

        public override bool Equals(
            object obj)
        {
            return Equals(obj as PublicKey);
        }

        public byte[] Export(
            KeyBlobFormat format)
        {
            int maxBlobSize = Key.GetKeyBlobSize(_algorithm, format);
            byte[] blob = new byte[maxBlobSize];
            int blobSize = Export(format, blob);
            Array.Resize(ref blob, blobSize);
            return blob;
        }

        public int Export(
            KeyBlobFormat format,
            Span<byte> blob)
        {
            return _algorithm.ExportPublicKey(_bytes, format, blob);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                // FNV-1a
                const uint FNV32Prime = 0x01000193U;
                const uint FNV32Basis = 0x811C9DC5U;

                uint hashCode = FNV32Basis;

                for (int i = 0; i < _bytes.Length; i++)
                {
                    hashCode = (hashCode ^ _bytes[i]) * FNV32Prime;
                }

                return (int)hashCode;
            }
        }
    }
}
