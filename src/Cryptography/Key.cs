using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Algorithm = {Algorithm}")]
    public sealed class Key : IDisposable
    {
        private readonly Algorithm _algorithm;
        private readonly KeyFlags _flags;
        private readonly SecureMemoryHandle _handle;
        private readonly PublicKey _publicKey;

        private bool _exported;

        public Key(
            Algorithm algorithm,
            KeyFlags flags = KeyFlags.None)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            _algorithm = algorithm;
            _flags = flags;
            _handle = algorithm.CreateKey(out _publicKey);
            _handle.MakeReadOnly();
        }

        internal Key(
            Algorithm algorithm,
            KeyFlags flags,
            SecureMemoryHandle handle,
            PublicKey publicKey)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(handle != null);

            _algorithm = algorithm;
            _flags = flags;
            _handle = handle;
            _publicKey = publicKey;
            _handle.MakeReadOnly();
        }

        public Algorithm Algorithm => _algorithm;

        public KeyFlags Flags => _flags;

        public PublicKey PublicKey => _publicKey;

        internal SecureMemoryHandle Handle => _handle;

        public static Key Create(
            Algorithm algorithm,
            KeyFlags flags = KeyFlags.None)
        {
            return new Key(algorithm, flags);
        }

        public static Key Import(
           Algorithm algorithm,
           ReadOnlySpan<byte> blob,
           KeyBlobFormat format,
           KeyFlags flags = KeyFlags.None)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (format == KeyBlobFormat.None)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(format));

            if (!algorithm.TryImportKey(blob, format, flags, out Key key))
            {
                throw new FormatException();
            }

            return key;
        }

        public static bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            KeyFlags flags,
            out Key result)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (format == KeyBlobFormat.None)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(format));

            return algorithm.TryImportKey(blob, format, flags, out result);
        }

        public void Dispose()
        {
            _handle.Dispose();
        }

        public byte[] Export(
            KeyBlobFormat format)
        {
            if (format == KeyBlobFormat.None)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(format));
            if (_handle.IsClosed)
                throw new ObjectDisposedException(GetType().FullName);

            bool exportSecretKey = format < KeyBlobFormat.None;
            bool allowExport = (_flags & KeyFlags.AllowExport) != 0;
            bool allowArchiving = (_flags & KeyFlags.AllowArchiving) != 0;

            if (exportSecretKey)
            {
                if (!allowExport)
                {
                    if (!allowArchiving || _exported)
                    {
                        throw new InvalidOperationException();
                    }
                }

                _exported = true;
            }

            if (!_algorithm.TryExportKey(this, format, out byte[] result))
            {
                throw new FormatException();
            }

            return result;
        }
    }
}
