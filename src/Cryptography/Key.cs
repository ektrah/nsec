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
            algorithm.CreateKey(out _handle, out byte[] publicKeyBytes);
            _publicKey = (publicKeyBytes != null) ? new PublicKey(_algorithm, publicKeyBytes) : null;
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

            if (!algorithm.TryImportKey(blob, format, out SecureMemoryHandle keyHandle, out byte[] publicKeyBytes))
            {
                throw new FormatException();
            }

            return new Key(algorithm, flags, keyHandle, (publicKeyBytes != null) ? new PublicKey(algorithm, publicKeyBytes) : null);
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

            if (!algorithm.TryImportKey(blob, format, out SecureMemoryHandle keyHandle, out byte[] publicKeyBytes))
            {
                result = null;
                return false;
            }

            result = new Key(algorithm, flags, keyHandle, (publicKeyBytes != null) ? new PublicKey(algorithm, publicKeyBytes) : null);
            return true;
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

            byte[] result;

            if (format < KeyBlobFormat.None)
            {
                bool allowExport = (_flags & KeyFlags.AllowExport) != 0;
                bool allowArchiving = (_flags & KeyFlags.AllowArchiving) != 0;

                if (!allowExport)
                {
                    if (!allowArchiving || _exported)
                    {
                        throw new InvalidOperationException();
                    }
                }

                _exported = true;

                if (!_algorithm.TryExportKey(_handle, format, out result))
                {
                    throw new FormatException();
                }
            }
            else
            {
                if (!_algorithm.TryExportPublicKey(_publicKey.Bytes, format, out result))
                {
                    throw new FormatException();
                }
            }

            return result;
        }
    }
}
