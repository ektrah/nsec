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
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));

            int seedSize = algorithm.GetDefaultSeedSize();

            SecureMemoryHandle keyHandle = null;
            byte[] publicKeyBytes = null;
            bool success = false;
            Span<byte> seed;

            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[seedSize];
                    seed = new Span<byte>(pointer, seedSize);
                }

                SecureRandom.GenerateBytesCore(seed);
                algorithm.CreateKey(seed, out keyHandle, out publicKeyBytes);
                success = true;
            }
            finally
            {
                sodium_memzero(ref seed.DangerousGetPinnableReference(), (UIntPtr)seed.Length);
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            keyHandle.MakeReadOnly();

            _algorithm = algorithm;
            _flags = flags;
            _handle = keyHandle;
            _publicKey = (publicKeyBytes) != null ? new PublicKey(algorithm, publicKeyBytes) : null;
        }

        internal Key(
            Algorithm algorithm,
            KeyFlags flags,
            SecureMemoryHandle keyHandle,
            byte[] publicKeyBytes)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(keyHandle != null);

            keyHandle.MakeReadOnly();

            _algorithm = algorithm;
            _flags = flags;
            _handle = keyHandle;
            _publicKey = (publicKeyBytes) != null ? new PublicKey(algorithm, publicKeyBytes) : null;
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
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));

            SecureMemoryHandle keyHandle = null;
            byte[] publicKeyBytes = null;
            bool success = false;

            try
            {
                success = algorithm.TryImportKey(blob, format, out keyHandle, out publicKeyBytes);
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

            return new Key(algorithm, flags, keyHandle, publicKeyBytes);
        }

        public static bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            KeyFlags flags,
            out Key result)
        {
            if (algorithm == null)
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));

            SecureMemoryHandle keyHandle = null;
            byte[] publicKeyBytes = null;
            bool success = false;

            try
            {
                success = algorithm.TryImportKey(blob, format, out keyHandle, out publicKeyBytes);
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            result = success ? new Key(algorithm, flags, keyHandle, publicKeyBytes) : null;
            return success;
        }

        public void Dispose()
        {
            _handle.Dispose();
        }

        public byte[] Export(
            KeyBlobFormat format)
        {
            if (format < 0)
            {
                if (_handle.IsClosed)
                {
                    throw Error.ObjectDisposed_Key();
                }

                bool allowExport = (_flags & KeyFlags.AllowExport) != 0;
                bool allowArchiving = (_flags & KeyFlags.AllowArchiving) != 0;

                if (!allowExport)
                {
                    if (!allowArchiving)
                    {
                        throw Error.InvalidOperation_ExportNotAllowed();
                    }
                    if (_exported)
                    {
                        throw Error.InvalidOperation_AlreadyArchived();
                    }
                }

                _exported = true;

                return _algorithm.ExportKey(_handle, format);
            }
            else
            {
                if (_publicKey == null)
                {
                    throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
                }

                return _algorithm.ExportPublicKey(_publicKey.Bytes, format);
            }
        }
    }
}
