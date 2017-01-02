using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public abstract class KeyDerivationAlgorithm : Algorithm
    {
        private readonly bool _usesSalt;

        internal KeyDerivationAlgorithm(
            bool usesSalt)
        {
            _usesSalt = usesSalt;
        }

        public bool UsesSalt => _usesSalt;

        public byte[] DeriveBytes(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (sharedSecret == null)
                throw new ArgumentNullException(nameof(sharedSecret));
            if (!_usesSalt && !salt.IsEmpty)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
            if (count < 0)
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
            if (!_usesSalt && !salt.IsEmpty)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
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
            if (!_usesSalt && !salt.IsEmpty)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            SecureMemoryHandle handle = algorithm.CreateDerivedKey();
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
