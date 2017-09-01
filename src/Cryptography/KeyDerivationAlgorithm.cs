using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A key derivation algorithm
    //
    //  Candidates
    //
    //      | Algorithm      | Reference | Salt Size | Info Size | Output Size   |
    //      | -------------- | --------- | --------- | --------- | ------------- |
    //      | ANSI X9.63 KDF | [1]       | 0         | any       | 0..L*(2^32-1) |
    //      | ConcatKDF Hash | [2]       | 0         | any       | 0..L*(2^32-1) |
    //      | ConcatKDF HMAC | [2]       | any       | any       | 0..L*(2^32-1) |
    //      | HKDF           | RFC 5869  | any       | any       | 0..L*255      |
    //
    //      L is the hash length of the hash function used.
    //
    //      [1] SEC 1: Elliptic Curve Cryptography, Section 3.6.1
    //      [2] NIST Special Publication 800-56A, Revision 2, Section 5.8
    //
    public abstract class KeyDerivationAlgorithm : Algorithm
    {
        private readonly int _maxOutputSize;
        private readonly bool _supportsSalt;

        internal KeyDerivationAlgorithm(
            bool supportsSalt,
            int maxOutputSize)
        {
            Debug.Assert(maxOutputSize > 0);

            _supportsSalt = supportsSalt;
            _maxOutputSize = maxOutputSize;
        }

        public int MaxOutputSize => _maxOutputSize;

        public bool SupportsSalt => _supportsSalt;

        public byte[] DeriveBytes(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (sharedSecret == null)
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            if (!_supportsSalt && !salt.IsEmpty)
                throw Error.Argument_SaltNotSupported(nameof(salt));
            if (count < 0)
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            if (count > MaxOutputSize)
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxOutputSize.ToString());
            if (count == 0)
                return Utilities.Empty<byte>();

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
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            if (!_supportsSalt && !salt.IsEmpty)
                throw Error.Argument_SaltNotSupported(nameof(salt));
            if (bytes.Length > MaxOutputSize)
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxOutputSize.ToString());
            if (Utilities.Overlap(bytes, info))
                throw Error.Argument_OverlapInfo(nameof(bytes));
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
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            if (!_supportsSalt && !salt.IsEmpty)
                throw Error.Argument_SaltNotSupported(nameof(salt));
            if (algorithm == null)
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));

            int seedSize = algorithm.GetDefaultSeedSize();
            if (seedSize > MaxOutputSize)
                throw Error.NotSupported_CreateKey();

            SecureMemoryHandle keyHandle = null;
            byte[] publicKeyBytes = null;
            bool success = false;
            Span<byte> seed;

            try
            {
                unsafe
                {
                    Debug.Assert(seedSize <= 64);
                    byte* pointer = stackalloc byte[seedSize];
                    seed = new Span<byte>(pointer, seedSize);
                }

                DeriveBytesCore(sharedSecret.Handle, salt, info, seed);
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

            return new Key(algorithm, flags, keyHandle, publicKeyBytes);
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
