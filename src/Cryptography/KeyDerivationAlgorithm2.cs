using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A key derivation algorithm following the "extract-then-expand" paradigm
    //
    //  Candidates
    //
    //      | Algorithm       | Reference | PRK Size  | Salt Size | Info Size | Output Size   |
    //      | --------------- | --------- | --------- | --------- | --------- | ------------- |
    //      | HKDF-SHA-256    | RFC 5869  | 32        | any       | any       | 0..8160       |
    //      | HKDF-SHA-512    | RFC 5869  | 64        | any       | any       | 0..16320      |
    //
    public abstract class KeyDerivationAlgorithm2 : KeyDerivationAlgorithm
    {
        private readonly int _pseudorandomKeySize;

        private protected KeyDerivationAlgorithm2(
            bool supportsSalt,
            int maxCount,
            int pseudorandomKeySize)
            : base(supportsSalt, maxCount)
        {
            Debug.Assert(pseudorandomKeySize > 0);
            Debug.Assert(maxCount > 0);

            _pseudorandomKeySize = pseudorandomKeySize;
        }

        public int PseudorandomKeySize => _pseudorandomKeySize;

        public byte[] Extract(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt)
        {
            if (inputKeyingMaterial.IsEmpty)
            {
                throw Error.Argument_InvalidIkmLength(nameof(inputKeyingMaterial));
            }
            if (salt.Length < MinSaltSize || salt.Length > MaxSaltSize)
            {
                throw (MinSaltSize == MaxSaltSize) ? Error.Argument_SaltLength(nameof(salt), MinSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), MinSaltSize, MaxSaltSize);
            }

            byte[] pseudorandomKey = new byte[_pseudorandomKeySize];
            ExtractCore(inputKeyingMaterial, salt, pseudorandomKey);
            return pseudorandomKey;
        }

        public void Extract(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            if (inputKeyingMaterial.IsEmpty)
            {
                throw Error.Argument_InvalidIkmLength(nameof(inputKeyingMaterial));
            }
            if (salt.Length < MinSaltSize || salt.Length > MaxSaltSize)
            {
                throw (MinSaltSize == MaxSaltSize) ? Error.Argument_SaltLength(nameof(salt), MinSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), MinSaltSize, MaxSaltSize);
            }
            if (pseudorandomKey.Length != _pseudorandomKeySize)
            {
                throw Error.Argument_InvalidPrkLengthExact(nameof(pseudorandomKey), _pseudorandomKeySize);
            }

            ExtractCore(inputKeyingMaterial, salt, pseudorandomKey);
        }

        public byte[] Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt)
        {
            if (sharedSecret == null)
            {
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            }
            if (salt.Length < MinSaltSize || salt.Length > MaxSaltSize)
            {
                throw (MinSaltSize == MaxSaltSize) ? Error.Argument_SaltLength(nameof(salt), MinSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), MinSaltSize, MaxSaltSize);
            }

            byte[] pseudorandomKey = new byte[_pseudorandomKeySize];
            ExtractCore(sharedSecret.Handle, salt, pseudorandomKey);
            return pseudorandomKey;
        }

        public void Extract(
            SharedSecret sharedSecret,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            if (sharedSecret == null)
            {
                throw Error.ArgumentNull_SharedSecret(nameof(sharedSecret));
            }
            if (salt.Length < MinSaltSize || salt.Length > MaxSaltSize)
            {
                throw (MinSaltSize == MaxSaltSize) ? Error.Argument_SaltLength(nameof(salt), MinSaltSize) : Error.Argument_SaltLengthRange(nameof(salt), MinSaltSize, MaxSaltSize);
            }
            if (pseudorandomKey.Length != _pseudorandomKeySize)
            {
                throw Error.Argument_InvalidPrkLengthExact(nameof(pseudorandomKey), _pseudorandomKeySize);
            }

            ExtractCore(sharedSecret.Handle, salt, pseudorandomKey);
        }

        public byte[] Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            int count)
        {
            if (pseudorandomKey.Length < _pseudorandomKeySize)
            {
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), _pseudorandomKeySize);
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
                return [];
            }

            byte[] bytes = new byte[count];
            ExpandCore(pseudorandomKey, info, bytes);
            return bytes;
        }

        public void Expand(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            if (pseudorandomKey.Length < _pseudorandomKeySize)
            {
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), _pseudorandomKeySize);
            }
            if (bytes.Length > MaxCount)
            {
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxCount);
            }
            if (bytes.Overlaps(pseudorandomKey))
            {
                throw Error.Argument_OverlapPrk(nameof(bytes));
            }
            if (bytes.Overlaps(info))
            {
                throw Error.Argument_OverlapInfo(nameof(bytes));
            }
            if (bytes.IsEmpty)
            {
                return;
            }

            ExpandCore(pseudorandomKey, info, bytes);
        }

        public Key ExpandKey(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (pseudorandomKey.Length < _pseudorandomKeySize)
            {
                throw Error.Argument_InvalidPrkLength(nameof(pseudorandomKey), _pseudorandomKeySize);
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
                    ExpandCore(pseudorandomKey, info, seed);
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

        private protected override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(!inputKeyingMaterial.IsEmpty);
            Debug.Assert(bytes.Length <= byte.MaxValue * _pseudorandomKeySize);

            Span<byte> pseudorandomKey = stackalloc byte[_pseudorandomKeySize];
            try
            {
                ExtractCore(inputKeyingMaterial, salt, pseudorandomKey);

                ExpandCore(pseudorandomKey, info, bytes);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(pseudorandomKey);
            }
        }

        private protected abstract void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes);

        private protected virtual void ExtractCore(
            SecureMemoryHandle sharedSecretHandle,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            bool mustCallRelease = false;
            try
            {
                sharedSecretHandle.DangerousAddRef(ref mustCallRelease);

                ExtractCore(sharedSecretHandle.DangerousGetSpan(), salt, pseudorandomKey);
            }
            finally
            {
                if (mustCallRelease)
                {
                    sharedSecretHandle.DangerousRelease();
                }
            }
        }

        private protected abstract void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey);
    }
}
