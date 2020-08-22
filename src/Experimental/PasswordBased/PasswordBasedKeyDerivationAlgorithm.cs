using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using NSec.Cryptography;

namespace NSec.Experimental.PasswordBased
{
    //
    //  A password hashing algorithm
    //
    //  Candidates
    //
    //      | Algorithm | Reference                 |
    //      | --------- | ------------------------- |
    //      | Argon2d   | draft-irtf-cfrg-argon2-11 |
    //      | Argon2i   | draft-irtf-cfrg-argon2-11 |
    //      | Argon2id  | draft-irtf-cfrg-argon2-11 |
    //      | scrypt    | RFC 7914                  |
    //
    public abstract class PasswordBasedKeyDerivationAlgorithm : Algorithm
    {
        private static Argon2i? s_Argon2i;
        private static Argon2id? s_Argon2id;
        private static Scrypt? s_Scrypt;

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

        public static Argon2i Argon2i
        {
            get
            {
                Argon2i? instance = s_Argon2i;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Argon2i, new Argon2i(), null);
                    instance = s_Argon2i;
                }
                return instance;
            }
        }

        public static Argon2id Argon2id
        {
            get
            {
                Argon2id? instance = s_Argon2id;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Argon2id, new Argon2id(), null);
                    instance = s_Argon2id;
                }
                return instance;
            }
        }

        public static Scrypt Scrypt
        {
            get
            {
                Scrypt? instance = s_Scrypt;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Scrypt, new Scrypt(), null);
                    instance = s_Scrypt;
                }
                return instance;
            }
        }

        public int MaxCount => _maxCount;

        public int SaltSize => _saltSize;

        public byte[] DeriveBytes(
            string password,
            ReadOnlySpan<byte> salt,
            int count)
        {
            if (password == null)
                throw Error.ArgumentNull_Password(nameof(password));
            if (salt.Length != SaltSize)
                throw Error.Argument_SaltLength(nameof(salt), SaltSize);
            if (count < 0)
                throw Error.ArgumentOutOfRange_DeriveNegativeCount(nameof(count));
            if (count > MaxCount)
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxCount);

            byte[] bytes = new byte[count];
            if (!TryDeriveBytesCore(MemoryMarshal.AsBytes(password.AsSpan()), salt, bytes))
            {
                throw new NotImplementedException(); // TODO
            }
            return bytes;
        }

        public void DeriveBytes(
            string password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            if (password == null)
                throw Error.ArgumentNull_Password(nameof(password));
            if (salt.Length != SaltSize)
                throw Error.Argument_SaltLength(nameof(salt), SaltSize);
            if (bytes.Length > MaxCount)
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxCount);
            if (bytes.IsEmpty)
                return;

            if (!TryDeriveBytesCore(MemoryMarshal.AsBytes(password.AsSpan()), salt, bytes))
            {
                throw new NotImplementedException(); // TODO
            }
        }

        public Key DeriveKey(
            string password,
            ReadOnlySpan<byte> salt,
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (password == null)
                throw Error.ArgumentNull_Password(nameof(password));
            if (salt.Length != SaltSize)
                throw Error.Argument_SaltLength(nameof(salt), SaltSize);
            if (algorithm == null)
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));

            int seedSize = algorithm.GetSeedSize();
            if (seedSize > MaxCount)
                throw Error.NotSupported_CreateKey();
            Debug.Assert(seedSize <= 64);

            ReadOnlyMemory<byte> memory = default;
            IMemoryOwner<byte>? owner = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    if (!TryDeriveBytesCore(MemoryMarshal.AsBytes(password.AsSpan()), salt, seed))
                    {
                        throw new NotImplementedException(); // TODO
                    }
                    algorithm.CreateKey(seed, creationParameters.GetMemoryPool(), out memory, out owner, out publicKey);
                    success = true;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(seed);
                }
            }
            finally
            {
                if (!success && owner != null)
                {
                    owner.Dispose();
                }
            }

            return new Key(algorithm, in creationParameters, memory, owner, publicKey);
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
