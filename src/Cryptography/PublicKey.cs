using System;
using System.Diagnostics;
using System.Linq;

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
            if (format == KeyBlobFormat.None)
                throw new ArgumentException();

            if (!algorithm.TryImportPublicKey(blob, format, out PublicKey result))
            {
                throw new FormatException();
            }

            return result;
        }

        public static bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey result)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (format == KeyBlobFormat.None)
                throw new ArgumentException();

            return algorithm.TryImportPublicKey(blob, format, out result);
        }

        public bool Equals(PublicKey other)
        {
            return (this == other)
                || (other != null)
                && (_algorithm == other._algorithm)
                && _bytes.SequenceEqual(other._bytes); // TODO: use BlockEquals
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as PublicKey);
        }

        public byte[] Export(KeyBlobFormat format)
        {
            if (format == KeyBlobFormat.None)
                throw new ArgumentException();

            if (!_algorithm.TryExportPublicKey(this, format, out byte[] result))
            {
                throw new FormatException();
            }

            return result;
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
