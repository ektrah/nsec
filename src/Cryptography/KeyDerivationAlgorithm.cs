using System;
using System.Diagnostics;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A key derivation algorithm
    //
    //  Candidates
    //
    //      | Algorithm       | Reference | Salt Size | Info Size | Output Size   |
    //      | --------------- | --------- | --------- | --------- | ------------- |
    //      | HKDF            | RFC 5869  | any       | any       | 0..L*(2^8-1)  |
    //      | ANSI X9.63 KDF  | [1]       | 0         | any       | 0..L*(2^32-1) |
    //      | ConcatKDF  Hash | [2][3]    | 0         | any       | 0..L*(2^32-1) |
    //      | ConcatKDF  HMAC | [2][3]    | any       | any       | 0..L*(2^32-1) |
    //      | SP 800-56C Hash | [4]       | 0         | any       | 0..L*(2^32-1) |
    //      | SP 800-56C HMAC | [4]       | any       | any       | 0..L*(2^32-1) |
    //      | SP 800-56C KMAC | [4]       | 2^2037–1  | any       | 0..L*(2^32-1) |
    //
    //      where L is the length (in bytes) of the output of the auxiliary function
    //
    //      [1] SEC 1: Elliptic Curve Cryptography, Section 3.6.1
    //      [2] NIST Special Publication 800-56A, Revision 3, Section 5.8
    //      [3] NIST Special Publication 800-56B, Revision 1, Section 5.5
    //      [4] NIST Special Publication 800-56C, Revision 1
    //
    public abstract class KeyDerivationAlgorithm : Algorithm
    {
        private static HkdfSha256? s_HkdfSha256;
        private static HkdfSha512? s_HkdfSha512;

        private readonly int _maxCount;
        private readonly int _maxSaltSize;
        private readonly int _minSaltSize;

        private protected KeyDerivationAlgorithm(
            bool supportsSalt,
            int maxCount)
        {
            Debug.Assert(maxCount > 0);

            _maxCount = maxCount;
            _maxSaltSize = supportsSalt ? int.MaxValue : 0;
            _minSaltSize = 0;
        }

        public static HkdfSha256 HkdfSha256
        {
            get
            {
                HkdfSha256? instance = s_HkdfSha256;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_HkdfSha256, new HkdfSha256(), null);
                    instance = s_HkdfSha256;
                }
                return instance;
            }
        }

        public static HkdfSha512 HkdfSha512
        {
            get
            {
                HkdfSha512? instance = s_HkdfSha512;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_HkdfSha512, new HkdfSha512(), null);
                    instance = s_HkdfSha512;
                }
                return instance;
            }
        }

        public int MaxCount => _maxCount;

        public int MaxSaltSize => _maxSaltSize;

        public int MinSaltSize => _minSaltSize;

        [Obsolete("The 'SupportsSalt' property has been deprecated. Use the 'MinSaltSize' and 'MaxSaltSize' properties instead.")]
        public bool SupportsSalt => _maxSaltSize != 0;

        public byte[] DeriveBytes(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (salt.Length < _minSaltSize || salt.Length > _maxSaltSize)
            {
                throw (_minSaltSize == _maxSaltSize) ? Error.Argument_SaltLength(nameof(salt), _minSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), _minSaltSize, _maxSaltSize);
            }
            if (count < 0)
            {
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            }
            if (count > _maxCount)
            {
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), _maxCount);
            }
            if (count == 0)
            {
                return Array.Empty<byte>();
            }

            byte[] bytes = new byte[count];
            DeriveBytesCore(inputKeyingMaterial, salt, info, bytes);
            return bytes;
        }

        public void DeriveBytes(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            if (salt.Length < _minSaltSize || salt.Length > _maxSaltSize)
            {
                throw (_minSaltSize == _maxSaltSize) ? Error.Argument_SaltLength(nameof(salt), _minSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), _minSaltSize, _maxSaltSize);
            }
            if (bytes.Length > _maxCount)
            {
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), _maxCount);
            }
            if (bytes.Overlaps(salt))
            {
                throw Error.Argument_OverlapSalt(nameof(bytes));
            }
            if (bytes.Overlaps(info))
            {
                throw Error.Argument_OverlapInfo(nameof(bytes));
            }
            if (bytes.IsEmpty)
            {
                return;
            }

            DeriveBytesCore(inputKeyingMaterial, salt, info, bytes);
        }

        public Key DeriveKey(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (salt.Length < _minSaltSize || salt.Length > _maxSaltSize)
            {
                throw (_minSaltSize == _maxSaltSize) ? Error.Argument_SaltLength(nameof(salt), _minSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), _minSaltSize, _maxSaltSize);
            }
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            int seedSize = algorithm.GetSeedSize();
            if (seedSize > _maxCount)
            {
                throw Error.NotSupported_CreateKey();
            }
            Debug.Assert(seedSize > 0 && seedSize <= 64);

            SecureMemoryHandle? keyHandle = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    DeriveBytesCore(inputKeyingMaterial, salt, info, seed);
                    algorithm.CreateKey(seed, out keyHandle, out publicKey);
                    success = true;
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
                }
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            return new Key(algorithm, in creationParameters, keyHandle, publicKey);
        }

        public byte[] DeriveBytes(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (sharedSecret == null)
            {
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            }
            if (salt.Length < _minSaltSize || salt.Length > _maxSaltSize)
            {
                throw (_minSaltSize == _maxSaltSize) ? Error.Argument_SaltLength(nameof(salt), _minSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), _minSaltSize, _maxSaltSize);
            }
            if (count < 0)
            {
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            }
            if (count > _maxCount)
            {
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), _maxCount);
            }
            if (count == 0)
            {
                return Array.Empty<byte>();
            }

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
            {
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            }
            if (salt.Length < _minSaltSize || salt.Length > _maxSaltSize)
            {
                throw (_minSaltSize == _maxSaltSize) ? Error.Argument_SaltLength(nameof(salt), _minSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), _minSaltSize, _maxSaltSize);
            }
            if (bytes.Length > _maxCount)
            {
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), _maxCount);
            }
            if (bytes.Overlaps(salt))
            {
                throw Error.Argument_OverlapSalt(nameof(bytes));
            }
            if (bytes.Overlaps(info))
            {
                throw Error.Argument_OverlapInfo(nameof(bytes));
            }
            if (bytes.IsEmpty)
            {
                return;
            }

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
            {
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            }
            if (salt.Length < _minSaltSize || salt.Length > _maxSaltSize)
            {
                throw (_minSaltSize == _maxSaltSize) ? Error.Argument_SaltLength(nameof(salt), _minSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), _minSaltSize, _maxSaltSize);
            }
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            int seedSize = algorithm.GetSeedSize();
            if (seedSize > _maxCount)
            {
                throw Error.NotSupported_CreateKey();
            }
            Debug.Assert(seedSize > 0 && seedSize <= 64);

            SecureMemoryHandle? keyHandle = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    DeriveBytesCore(sharedSecret.Handle, salt, info, seed);
                    algorithm.CreateKey(seed, out keyHandle, out publicKey);
                    success = true;
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
                }
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            return new Key(algorithm, in creationParameters, keyHandle, publicKey);
        }

        internal sealed override int GetKeySize()
        {
            throw Error.InvalidOperation_InternalError();
        }

        internal sealed override int GetPublicKeySize()
        {
            throw Error.InvalidOperation_InternalError();
        }

        internal sealed override int GetSeedSize()
        {
            throw Error.NotSupported_CreateKey();
        }

        private protected virtual void DeriveBytesCore(
            SecureMemoryHandle sharedSecretHandle,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            bool mustCallRelease = false;
            try
            {
                sharedSecretHandle.DangerousAddRef(ref mustCallRelease);

                DeriveBytesCore(sharedSecretHandle.DangerousGetSpan(), salt, info, bytes);
            }
            finally
            {
                if (mustCallRelease)
                {
                    sharedSecretHandle.DangerousRelease();
                }
            }
        }

        private protected abstract void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes);
    }
}
