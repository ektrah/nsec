using System;
using System.ComponentModel;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Algorithm = {Algorithm}")]
    public sealed class Key : IDisposable
    {
        private readonly Algorithm _algorithm;
        private readonly KeyExportPolicies _exportPolicy;
        private readonly SecureMemoryHandle _handle;
        private readonly PublicKey? _publicKey;

        private bool _exported;

        public Key(
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            int seedSize = algorithm.GetSeedSize();
            Debug.Assert(seedSize > 0 && seedSize <= 64);

            SecureMemoryHandle? keyHandle = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    System.Security.Cryptography.RandomNumberGenerator.Fill(seed);
                    algorithm.CreateKey(seed, out keyHandle, out publicKey);
                    success = true;
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
                }
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            _algorithm = algorithm;
            _exportPolicy = creationParameters.ExportPolicy;
            _handle = keyHandle;
            _publicKey = publicKey;
        }

        internal Key(
            Algorithm algorithm,
            ref readonly KeyCreationParameters creationParameters,
            SecureMemoryHandle keyHandle,
            PublicKey? publicKey)
        {
            _algorithm = algorithm;
            _exportPolicy = creationParameters.ExportPolicy;
            _handle = keyHandle;
            _publicKey = publicKey;
        }

        public Algorithm Algorithm => _algorithm;

        public KeyExportPolicies ExportPolicy => _exportPolicy;

        public bool HasPublicKey => _publicKey != null;

        public PublicKey PublicKey => _publicKey ?? throw Error.InvalidOperation_NoPublicKey();

        public int Size => _algorithm.GetKeySize();

        internal SecureMemoryHandle Handle => _handle;

        public static Key Create(
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            return new Key(algorithm, in creationParameters);
        }

        public static Key Import(
           Algorithm algorithm,
           ReadOnlySpan<byte> blob,
           KeyBlobFormat format,
           in KeyCreationParameters creationParameters = default)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            SecureMemoryHandle? keyHandle = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                success = algorithm.TryImportKey(blob, format, out keyHandle, out publicKey);
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            if (!success || keyHandle == null)
            {
                throw Error.Format_InvalidBlob();
            }

            return new Key(algorithm, in creationParameters, keyHandle, publicKey);
        }

        public static bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out Key? result,
            in KeyCreationParameters creationParameters = default)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            SecureMemoryHandle? keyHandle = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                success = algorithm.TryImportKey(blob, format, out keyHandle, out publicKey);
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            result = success && keyHandle != null ? new Key(algorithm, in creationParameters, keyHandle, publicKey) : null;
            return success;
        }

        public void Dispose()
        {
            _handle.Dispose();
        }

        public byte[] Export(
            KeyBlobFormat format)
        {
            byte[] blob;
            int blobSize;

            if (format < 0)
            {
                ObjectDisposedException.ThrowIf(_handle.IsClosed, this);

                if ((_exportPolicy & KeyExportPolicies.AllowPlaintextExport) == 0)
                {
                    if ((_exportPolicy & KeyExportPolicies.AllowPlaintextArchiving) == 0)
                    {
                        throw Error.InvalidOperation_ExportNotAllowed();
                    }
                    if (_exported)
                    {
                        throw Error.InvalidOperation_AlreadyArchived();
                    }
                }

                _algorithm.TryExportKey(_handle, format, [], out blobSize);
                blob = new byte[blobSize];

                if (!_algorithm.TryExportKey(_handle, format, blob, out blobSize))
                {
                    throw Error.InvalidOperation_InternalError();
                }

                Debug.Assert(blobSize == blob.Length);
                _exported = true;
                return blob;
            }
            else
            {
                if (_publicKey == null)
                {
                    throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
                }

                _algorithm.TryExportPublicKey(_publicKey, format, [], out blobSize);
                blob = new byte[blobSize];

                if (!_algorithm.TryExportPublicKey(_publicKey, format, blob, out blobSize))
                {
                    throw Error.InvalidOperation_InternalError();
                }

                Debug.Assert(blobSize == blob.Length);
                return blob;
            }
        }

        public int GetExportBlobSize(
            KeyBlobFormat format)
        {
            int blobSize;

            if (format < 0)
            {
                ObjectDisposedException.ThrowIf(_handle.IsClosed, this);

                _algorithm.TryExportKey(_handle, format, [], out blobSize);
            }
            else
            {
                if (_publicKey == null)
                {
                    throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
                }

                _algorithm.TryExportPublicKey(_publicKey, format, [], out blobSize);
            }

            return blobSize;
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString()
        {
            return typeof(Key).ToString();
        }

        public bool TryExport(
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            if (format < 0)
            {
                ObjectDisposedException.ThrowIf(_handle.IsClosed, this);

                if ((_exportPolicy & KeyExportPolicies.AllowPlaintextExport) == 0)
                {
                    if ((_exportPolicy & KeyExportPolicies.AllowPlaintextArchiving) == 0)
                    {
                        throw Error.InvalidOperation_ExportNotAllowed();
                    }
                    if (_exported)
                    {
                        throw Error.InvalidOperation_AlreadyArchived();
                    }
                }

                if (!_algorithm.TryExportKey(_handle, format, blob, out blobSize))
                {
                    return false;
                }

                _exported = true;
                return true;
            }
            else
            {
                if (_publicKey == null)
                {
                    throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
                }

                if (!_algorithm.TryExportPublicKey(_publicKey, format, blob, out blobSize))
                {
                    return false;
                }

                return true;
            }
        }
    }
}
