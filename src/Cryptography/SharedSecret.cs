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
            SecureMemoryHandle sharedSecretHandle)
        {
            Debug.Assert(sharedSecretHandle != null);

            sharedSecretHandle.MakeReadOnly();

            _handle = sharedSecretHandle;
        }

        public int Size => _handle.Length;

        internal SecureMemoryHandle Handle => _handle;

        public static SharedSecret Import(
            ReadOnlySpan<byte> sharedSecret)
        {
            if (sharedSecret.Length > 128)
            {
                throw Error.Argument_SharedSecretLength(nameof(sharedSecret), 128.ToString());
            }

            Sodium.Initialize();

            SecureMemoryHandle sharedSecretHandle = null;
            bool success = false;

            try
            {
                SecureMemoryHandle.Import(sharedSecret, out sharedSecretHandle);
                success = true;
            }
            finally
            {
                if (!success && sharedSecretHandle != null)
                {
                    sharedSecretHandle.Dispose();
                }
            }

            return new SharedSecret(sharedSecretHandle);
        }

        public void Dispose()
        {
            _handle.Dispose();
        }
    }
}
