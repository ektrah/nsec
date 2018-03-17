using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Algorithm = {Algorithm}")]
    public sealed class Key : IDisposable
    {
        private readonly Algorithm _algorithm;
        private readonly KeyExportPolicies _exportPolicy;
        private readonly SecureMemoryHandle _handle;
        private readonly PublicKey _publicKey;

        private bool _exported;

        public Key(
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            int seedSize = algorithm.GetDefaultSeedSize();
            Debug.Assert(seedSize <= 64);

            SecureMemoryHandle keyHandle = null;
            PublicKey publicKey = null;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    RandomGenerator.Default.GenerateBytes(seed);
                    algorithm.CreateKey(seed, out keyHandle, out publicKey);
                    success = true;
                }
                finally
                {
                    sodium_memzero(ref MemoryMarshal.GetReference(seed), (UIntPtr)seed.Length);
                }
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            keyHandle.MakeReadOnly();

            _algorithm = algorithm;
            _exportPolicy = creationParameters.ExportPolicy;
            _handle = keyHandle;
            _publicKey = publicKey;
        }

        internal Key(
            Algorithm algorithm,
            in KeyCreationParameters creationParameters,
            SecureMemoryHandle keyHandle,
            PublicKey publicKey)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(keyHandle != null);

            keyHandle.MakeReadOnly();

            _algorithm = algorithm;
            _exportPolicy = creationParameters.ExportPolicy;
            _handle = keyHandle;
            _publicKey = publicKey;
        }

        public Algorithm Algorithm => _algorithm;

        public KeyExportPolicies ExportPolicy => _exportPolicy;

        public PublicKey PublicKey => _publicKey;

        internal SecureMemoryHandle Handle => _handle;

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

            SecureMemoryHandle keyHandle = null;
            PublicKey publicKey = null;
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

            if (!success)
            {
                throw Error.Format_InvalidBlob();
            }

            return new Key(algorithm, in creationParameters, keyHandle, publicKey);
        }

        public static bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out Key result,
            in KeyCreationParameters creationParameters = default)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            SecureMemoryHandle keyHandle = null;
            PublicKey publicKey = null;
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

            result = success ? new Key(algorithm, in creationParameters, keyHandle, publicKey) : null;
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
                if (_handle.IsClosed)
                {
                    throw Error.ObjectDisposed_Key();
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

                _exported = true;

                _algorithm.TryExportKey(_handle, format, Span<byte>.Empty, out blobSize);
                blob = new byte[blobSize];

                if (!_algorithm.TryExportKey(_handle, format, blob, out blobSize))
                {
                    throw Error.Cryptographic_InternalError();
                }

                Debug.Assert(blobSize == blob.Length);
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
                    throw Error.Cryptographic_InternalError();
                }

                Debug.Assert(blobSize == blob.Length);
                return blob;
            }
        }
    }
}
