using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A key derivation algorithm
    //
    //  Examples
    //
    //      | Algorithm      | Reference | Salt Size | Output Size   |
    //      | -------------- | --------- | --------- | ------------- |
    //      | ANSI X9.63 KDF | [1]       | 0         | 0..L*(2^32-1) |
    //      | ConcatKDF Hash | [2]       | 0         | 0..L*(2^32-1) |
    //      | ConcatKDF HMAC | [2]       | any       | 0..L*(2^32-1) |
    //      | HKDF           | RFC 5869  | any       | 0..L*255      |
    //
    //      L is the hash length of the underlying hash function.
    //
    //      [1] SEC 1: Elliptic Curve Cryptography, Section 3.6.1
    //      [2] NIST Special Publication 800-56A, Revision 2, Section 5.8
    //
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
            DeriveBytesCore(sharedSecret.Handle, salt, info, bytes);
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

            DeriveBytesCore(sharedSecret.Handle, salt, info, bytes);
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
            DeriveKeyCore(sharedSecret.Handle, salt, info, handle);
            return new Key(algorithm, flags, handle, null);
        }

        internal abstract void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes);

        internal virtual void DeriveBytesCore(
            SecureMemoryHandle inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            bool addedRef = false;
            try
            {
                inputKeyingMaterial.DangerousAddRef(ref addedRef);

                DeriveBytesCore(inputKeyingMaterial.DangerousGetSpan(), salt, info, bytes);
            }
            finally
            {
                if (addedRef)
                {
                    inputKeyingMaterial.DangerousRelease();
                }
            }
        }

        internal virtual void DeriveKeyCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            SecureMemoryHandle keyHandle)
        {
            bool addedRef = false;
            try
            {
                keyHandle.DangerousAddRef(ref addedRef);

                DeriveBytesCore(inputKeyingMaterial, salt, info, keyHandle.DangerousGetSpan());
            }
            finally
            {
                if (addedRef)
                {
                    keyHandle.DangerousRelease();
                }
            }
        }

        internal virtual void DeriveKeyCore(
            SecureMemoryHandle inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            SecureMemoryHandle keyHandle)
        {
            bool addedRef = false;
            try
            {
                keyHandle.DangerousAddRef(ref addedRef);

                DeriveBytesCore(inputKeyingMaterial, salt, info, keyHandle.DangerousGetSpan());
            }
            finally
            {
                if (addedRef)
                {
                    keyHandle.DangerousRelease();
                }
            }
        }
    }
}
