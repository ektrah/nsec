using System;
using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Algorithm = {Algorithm}")]
    public sealed class Key : IDisposable
    {
        private readonly Algorithm _algorithm;
        private readonly IDisposable _disposable;
        private readonly KeyExportPolicies _exportPolicy;
        private readonly ReadOnlyMemory<byte> _memory;
        private readonly PublicKey? _publicKey;

        private bool _disposed;
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
            Debug.Assert(seedSize <= 64);

            ReadOnlyMemory<byte> memory = default;
            IMemoryOwner<byte>? owner = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    RandomGenerator.Default.GenerateBytes(seed);
                    algorithm.CreateKey(seed, creationParameters.GetMemoryPool(), out memory, out owner, out publicKey);
                    success = true;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(seed);
                }
            }
            finally
            {
                if (!success && owner != null)
                {
                    owner.Dispose();
                }
            }

            _algorithm = algorithm;
            _exportPolicy = creationParameters.ExportPolicy;
            _memory = memory;
            _disposable = owner;
            _publicKey = publicKey;
        }

        internal Key(
            Algorithm algorithm,
            in KeyCreationParameters creationParameters,
            ReadOnlyMemory<byte> memory,
            IDisposable owner,
            PublicKey? publicKey)
        {
            _algorithm = algorithm;
            _exportPolicy = creationParameters.ExportPolicy;
            _memory = memory;
            _disposable = owner;
            _publicKey = publicKey;
        }

        public Algorithm Algorithm => _algorithm;

        public KeyExportPolicies ExportPolicy => _exportPolicy;

        public bool HasPublicKey => _publicKey != null;

        public PublicKey PublicKey => _publicKey ?? throw Error.InvalidOperation_NoPublicKey();

        public int Size => _algorithm.GetKeySize();

        internal ReadOnlySpan<byte> Span
        {
            get
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(typeof(Key).FullName);
                }

                return _memory.Span;
            }
        }

        public static Key Create(
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            return RandomGenerator.Default.GenerateKey(algorithm, in creationParameters);
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

            ReadOnlyMemory<byte> memory = default;
            IMemoryOwner<byte>? owner = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                success = algorithm.TryImportKey(blob, format, creationParameters.GetMemoryPool(), out memory, out owner, out publicKey);
            }
            finally
            {
                if (!success && owner != null)
                {
                    owner.Dispose();
                }
            }

            if (!success || owner == null)
            {
                throw Error.Format_InvalidBlob();
            }

            return new Key(algorithm, in creationParameters, memory, owner, publicKey);
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

            ReadOnlyMemory<byte> memory = default;
            IMemoryOwner<byte>? owner = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                success = algorithm.TryImportKey(blob, format, creationParameters.GetMemoryPool(), out memory, out owner, out publicKey);
            }
            finally
            {
                if (!success && owner != null)
                {
                    owner.Dispose();
                }
            }

            result = success && owner != null ? new Key(algorithm, in creationParameters, memory, owner, publicKey) : null;
            return success;
        }

        public void Dispose()
        {
            _disposed = true;
            _disposable.Dispose();
        }

        public byte[] Export(
            KeyBlobFormat format)
        {
            byte[] blob;
            int blobSize;

            if (format < 0)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(typeof(Key).FullName);
                }

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

                _algorithm.TryExportKey(_memory.Span, format, Span<byte>.Empty, out blobSize);
                blob = new byte[blobSize];

                if (!_algorithm.TryExportKey(_memory.Span, format, blob, out blobSize))
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

                _algorithm.TryExportPublicKey(_publicKey, format, Span<byte>.Empty, out blobSize);
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
                if (_disposed)
                {
                    throw new ObjectDisposedException(typeof(Key).FullName);
                }

                _algorithm.TryExportKey(_memory.Span, format, Span<byte>.Empty, out blobSize);
            }
            else
            {
                if (_publicKey == null)
                {
                    throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
                }

                _algorithm.TryExportPublicKey(_publicKey, format, Span<byte>.Empty, out blobSize);
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
                if (_disposed)
                {
                    throw new ObjectDisposedException(typeof(Key).FullName);
                }

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

                if (!_algorithm.TryExportKey(_memory.Span, format, blob, out blobSize))
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
