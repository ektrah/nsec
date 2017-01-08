using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Size = {Size}")]
    public sealed class SharedSecret : IDisposable
    {
        private readonly SecureMemoryHandle _handle;

        internal SharedSecret(
            SecureMemoryHandle handle)
        {
            Debug.Assert(handle != null);

            handle.MakeReadOnly();

            _handle = handle;
        }

        public int Size => _handle.Length;

        internal SecureMemoryHandle Handle => _handle;

        public static SharedSecret Import(
            ReadOnlySpan<byte> sharedSecret)
        {
            if (sharedSecret.Length > 128)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(sharedSecret));

            Sodium.Initialize();

            SecureMemoryHandle handle = null;
            bool success = false;

            try
            {
                handle = SecureMemoryHandle.Alloc(sharedSecret.Length);
                handle.Import(sharedSecret);
                success = true;
            }
            finally
            {
                if (!success && handle != null)
                {
                    handle.Dispose();
                }
            }

            return new SharedSecret(handle);
        }

        public void Dispose()
        {
            _handle.Dispose();
        }
    }
}
