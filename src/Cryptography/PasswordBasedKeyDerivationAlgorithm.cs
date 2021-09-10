using System;
using System.Diagnostics;
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
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            int count)
        {
            if (salt.Length != SaltSize)
                throw Error.Argument_SaltLength(nameof(salt), SaltSize);
            if (count < 0)
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            if (count > MaxCount)
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxCount);

            byte[] bytes = new byte[count];
            if (!TryDeriveBytesCore(password, salt, bytes))
            {
                throw new NotImplementedException(); // TODO
            }
            return bytes;
        }

        public void DeriveBytes(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            if (salt.Length != SaltSize)
                throw Error.Argument_SaltLength(nameof(salt), SaltSize);
            if (bytes.Length > MaxCount)
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxCount);
            if (bytes.IsEmpty)
                return;

            if (!TryDeriveBytesCore(password, salt, bytes))
            {
                throw new NotImplementedException(); // TODO
            }
        }

        public Key DeriveKey(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (salt.Length != SaltSize)
                throw Error.Argument_SaltLength(nameof(salt), SaltSize);
            if (algorithm == null)
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));

            int seedSize = algorithm.GetSeedSize();
            if (seedSize > MaxCount)
                throw Error.NotSupported_CreateKey();
            Debug.Assert(seedSize <= 64);

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
                        throw new NotImplementedException(); // TODO
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
