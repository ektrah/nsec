using System;
using System.ComponentModel;
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
            _handle = sharedSecretHandle;
        }

        public int Size => _handle.Size;

        internal SecureMemoryHandle Handle => _handle;

        public static SharedSecret Import(
            ReadOnlySpan<byte> sharedSecret,
            in SharedSecretCreationParameters creationParameters = default)
        {
            if (sharedSecret.Length > 128)
            {
                throw Error.Argument_SharedSecretLength(nameof(sharedSecret), 128);
            }

            Sodium.Initialize();

            SecureMemoryHandle? sharedSecretHandle = default;
            bool success = false;

            try
            {
                ImportCore(sharedSecret, out sharedSecretHandle);
                success = true;
            }
            finally
            {
                if (!success && sharedSecretHandle != null)
                {
                    sharedSecretHandle.Dispose();
                }
            }

            if (!success || sharedSecretHandle == null)
            {
                throw Error.Format_InvalidBlob();
            }

            return new SharedSecret(sharedSecretHandle);
        }

        public void Dispose()
        {
            _handle.Dispose();
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString()
        {
            return typeof(SharedSecret).ToString();
        }

        private static void ImportCore(
            ReadOnlySpan<byte> sharedSecret,
            out SecureMemoryHandle? sharedSecretHandle)
        {
            sharedSecretHandle = SecureMemoryHandle.CreateFrom(sharedSecret);
        }
    }
}
