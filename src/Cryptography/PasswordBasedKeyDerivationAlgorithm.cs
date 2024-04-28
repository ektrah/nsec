using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A password hashing algorithm
    //
    //  Candidates
    //
    //      | Algorithm | Reference |
    //      | --------- | --------- |
    //      | Argon2d   | RFC 9106  |
    //      | Argon2i   | RFC 9106  |
    //      | Argon2id  | RFC 9106  |
    //      | scrypt    | RFC 7914  |
    //
    public abstract class PasswordBasedKeyDerivationAlgorithm : Algorithm
    {
        private readonly int _maxCount;
        private readonly int _maxSaltSize;
        private readonly int _minSaltSize;

        private protected PasswordBasedKeyDerivationAlgorithm(
            int saltSize,
            int maxCount)
        {
            Debug.Assert(saltSize > 0);
            Debug.Assert(maxCount > 0);

            _maxCount = maxCount;
            _maxSaltSize = saltSize;
            _minSaltSize = saltSize;
        }

        public int MaxCount => _maxCount;

        public int MaxSaltSize => _maxSaltSize;

        public int MinSaltSize => _minSaltSize;

        public static Argon2id Argon2id(
            in Argon2Parameters parameters)
        {
            return new Argon2id(in parameters);
        }

        public static Scrypt Scrypt(
            in ScryptParameters parameters)
        {
            return new Scrypt(in parameters);
        }

        public byte[] DeriveBytes(
            string password,
            ReadOnlySpan<byte> salt,
            int count)
        {
            if (password == null)
            {
                throw Error.ArgumentNull_Password(nameof(password));
            }

            return DeriveBytes(MemoryMarshal.AsBytes(password.AsSpan()), salt, count);
        }

        public void DeriveBytes(
            string password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            if (password == null)
            {
                throw Error.ArgumentNull_Password(nameof(password));
            }

            DeriveBytes(MemoryMarshal.AsBytes(password.AsSpan()), salt, bytes);
        }

        public Key DeriveKey(
            string password,
            ReadOnlySpan<byte> salt,
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (password == null)
            {
                throw Error.ArgumentNull_Password(nameof(password));
            }

            return DeriveKey(MemoryMarshal.AsBytes(password.AsSpan()), salt, algorithm, in creationParameters);
        }

        public byte[] DeriveBytes(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
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
                return [];
            }

            byte[] bytes = new byte[count];
            if (!TryDeriveBytesCore(password, salt, bytes))
            {
                throw Error.Cryptographic_PasswordBasedKeyDerivationFailed();
            }
            return bytes;
        }

        public void DeriveBytes(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
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
            if (bytes.IsEmpty)
            {
                return;
            }

            if (!TryDeriveBytesCore(password, salt, bytes))
            {
                throw Error.Cryptographic_PasswordBasedKeyDerivationFailed();
            }
        }

        public Key DeriveKey(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
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
                    if (!TryDeriveBytesCore(password, salt, seed))
                    {
                        throw Error.Cryptographic_PasswordBasedKeyDerivationFailed();
                    }
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

        internal abstract bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes);
    }
}
