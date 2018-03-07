using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
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

        private protected KeyDerivationAlgorithm(
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
            if (bytes.Overlaps(salt))
                throw Error.Argument_OverlapSalt(nameof(bytes));
            if (bytes.Overlaps(info))
                throw Error.Argument_OverlapInfo(nameof(bytes));

            DeriveBytesCore(sharedSecret.Handle, salt, info, bytes);
        }

        public Key DeriveKey(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
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
            Debug.Assert(seedSize <= 64);

            SecureMemoryHandle keyHandle = null;
            byte[] publicKeyBytes = null;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    DeriveBytesCore(sharedSecret.Handle, salt, info, seed);
                    algorithm.CreateKey(seed, out keyHandle, out publicKeyBytes);
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

            return new Key(algorithm, in creationParameters, keyHandle, publicKeyBytes);
        }

        private protected abstract void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes);

        private protected virtual void DeriveBytesCore(
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
    }
}
