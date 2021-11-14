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
        private readonly int _saltSize;

        private protected PasswordBasedKeyDerivationAlgorithm(
            int saltSize,
            int maxCount)
        {
            Debug.Assert(saltSize > 0);
            Debug.Assert(maxCount > 0);

            _saltSize = saltSize;
            _maxCount = maxCount;
        }

        public int MaxCount => _maxCount;

        public int MaxSaltSize => _saltSize;

        public int MinSaltSize => _saltSize;

        [Obsolete("The 'SaltSize' property has been deprecated. Use the 'MinSaltSize' and 'MaxSaltSize' properties instead.")]
        public int SaltSize => _saltSize;

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
            if (salt.Length < MinSaltSize || salt.Length > MaxSaltSize)
            {
                throw (MinSaltSize == MaxSaltSize) ? Error.Argument_SaltLength(nameof(salt), MinSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), MinSaltSize, MaxSaltSize);
            }
            if (count < 0)
            {
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            }
            if (count > MaxCount)
            {
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxCount);
            }
            if (count == 0)
            {
                return Array.Empty<byte>();
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
            if (salt.Length < MinSaltSize || salt.Length > MaxSaltSize)
            {
                throw (MinSaltSize == MaxSaltSize) ? Error.Argument_SaltLength(nameof(salt), MinSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), MinSaltSize, MaxSaltSize);
            }
            if (bytes.Length > MaxCount)
            {
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxCount);
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
            if (salt.Length < MinSaltSize || salt.Length > MaxSaltSize)
            {
                throw (MinSaltSize == MaxSaltSize) ? Error.Argument_SaltLength(nameof(salt), MinSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), MinSaltSize, MaxSaltSize);
            }
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            int seedSize = algorithm.GetSeedSize();
            if (seedSize > MaxCount)
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
