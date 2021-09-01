using System;
using System.ComponentModel;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    /// <summary>
    /// represents a shared secret
    /// </summary>
    [DebuggerDisplay("Size = {Size}")]
    public sealed class SharedSecret : IDisposable
    {
        /// <summary>
        /// handle to the underlying secure memory structure
        /// </summary>
        private readonly SecureMemoryHandle _handle;
        /// <summary>
        /// ctor using a provided handle
        /// </summary>
        /// <param name="sharedSecretHandle"></param>
        internal SharedSecret(
            SecureMemoryHandle sharedSecretHandle)
        {
            _handle = sharedSecretHandle;
        }
        /// <summary>
        /// length of the key
        /// </summary>
        public int Size => _handle.Size;
        /// <summary>
        /// internally exposed handle
        /// </summary>
        internal SecureMemoryHandle Handle => _handle;
        /// <summary>
        /// imports a shared key
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="creationParameters"></param>
        /// <returns></returns>
        [Obsolete("The 'Import' method is obsolete. Use the method overloads in the 'KeyDerivationAlgorithm' class that accept a 'ReadOnlySpan<byte>' directly instead.")]
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
        /// <summary>
        /// disposes the secret
        /// </summary>
        public void Dispose()
        {
            _handle.Dispose();
        }
        /// <summary>
        /// to string
        /// </summary>
        /// <returns></returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString()
        {
            return typeof(SharedSecret).ToString();
        }
        /// <summary>
        /// copies secret data to the given destination
        /// </summary>
        /// <param name="destination"></param>
        public void CopyTo(Span<byte> destination)
        {
            _handle.CopyTo(destination);
        }
        /// <summary>
        /// creates a new secret via import
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="sharedSecretHandle"></param>
        private static void ImportCore(
            ReadOnlySpan<byte> sharedSecret,
            out SecureMemoryHandle? sharedSecretHandle)
        {
            sharedSecretHandle = SecureMemoryHandle.CreateFrom(sharedSecret);
        }
    }
}
