using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public abstract class KeyDerivationAlgorithm : Algorithm
    {
        private readonly int _maxOutputSize;
        private readonly int _maxSaltSize;

        internal KeyDerivationAlgorithm(
            int maxSaltSize,
            int maxOutputSize)
        {
            Debug.Assert(maxSaltSize >= 0);
            Debug.Assert(maxOutputSize > 0);

            _maxSaltSize = maxSaltSize;
            _maxOutputSize = maxOutputSize;
        }

        public int MaxOutputSize => _maxOutputSize;

        public int MaxSaltSize => _maxSaltSize;

        public byte[] DeriveBytes(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (sharedSecret == null)
                throw new ArgumentNullException(nameof(sharedSecret));
            if (salt.Length > MaxSaltSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count > MaxOutputSize)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count == 0)
                return new byte[0];

            byte[] bytes = new byte[count];
            DeriveBytesCore(sharedSecret, salt, info, bytes);
            return bytes;
        }

        public void DeriveBytes(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            if (sharedSecret == null)
                throw new ArgumentNullException(nameof(sharedSecret));
            if (salt.Length > MaxSaltSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
            if (bytes.Length > MaxOutputSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(bytes));
            if (bytes.IsEmpty)
                return;

            DeriveBytesCore(sharedSecret, salt, info, bytes);
        }

        public Key DeriveKey(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Algorithm algorithm,
            KeyFlags flags = KeyFlags.None)
        {
            if (sharedSecret == null)
                throw new ArgumentNullException(nameof(sharedSecret));
            if (salt.Length > MaxSaltSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            int keySize = algorithm.GetDerivedKeySize();
            if (keySize > MaxOutputSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(algorithm));

            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(keySize);
            DeriveKeyCore(sharedSecret, salt, info, handle);
            return new Key(algorithm, flags, handle, null);
        }

        internal abstract void DeriveBytesCore(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes);

        internal virtual void DeriveKeyCore(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            SecureMemoryHandle key)
        {
            bool addedRef = false;
            try
            {
                key.DangerousAddRef(ref addedRef);

                DeriveBytesCore(sharedSecret, salt, info, key.DangerousGetSpan());
            }
            finally
            {
                if (addedRef)
                {
                    key.DangerousRelease();
                }
            }
        }
    }
}
