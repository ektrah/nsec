using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
            if (Unsafe.SizeOf<PublicKeyBytes>() != 8 * sizeof(uint))
            {
                throw Error.InvalidOperation_InternalError();
            }
            if (other == this)
            {
                return true;
            }
            if (other == null || other._algorithm != _algorithm)
            {
                return false;
            }

            ref byte x = ref Unsafe.As<PublicKeyBytes, byte>(ref _bytes);
            ref byte y = ref Unsafe.As<PublicKeyBytes, byte>(ref other._bytes);

            return Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 0 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 0 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 1 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 1 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 2 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 2 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 3 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 3 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 4 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 4 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 5 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 5 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 6 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 6 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 7 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 7 * sizeof(uint)));
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
            _algorithm.TryExportPublicKey(this, format, Span<byte>.Empty, out int blobSize);
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
            _algorithm.TryExportPublicKey(this, format, Span<byte>.Empty, out int blobSize);
            return blobSize;
        }

        public override int GetHashCode()
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != 8 * sizeof(uint))
            {
                throw Error.InvalidOperation_InternalError();
            }

            ref byte x = ref Unsafe.As<PublicKeyBytes, byte>(ref _bytes);
            uint hashCode = unchecked((uint)_algorithm.GetHashCode());

            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 0 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 1 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 2 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 3 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 4 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 5 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 6 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 7 * sizeof(uint))));

            return unchecked((int)hashCode);
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
