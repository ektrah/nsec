using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;

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
        private readonly bool _supportsSalt;

        private protected KeyDerivationAlgorithm(
            bool supportsSalt,
            int maxCount)
        {
            Debug.Assert(maxCount > 0);

            _supportsSalt = supportsSalt;
            _maxCount = maxCount;
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
            if (count > MaxCount)
                throw Error.ArgumentOutOfRange_DeriveInvalidCount(nameof(count), MaxCount);

            byte[] bytes = new byte[count];
            DeriveBytesCore(sharedSecret.Span, salt, info, bytes);
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
            if (bytes.Length > MaxCount)
                throw Error.Argument_DeriveInvalidCount(nameof(bytes), MaxCount);
            if (bytes.Overlaps(salt))
                throw Error.Argument_OverlapSalt(nameof(bytes));
            if (bytes.Overlaps(info))
                throw Error.Argument_OverlapInfo(nameof(bytes));

            DeriveBytesCore(sharedSecret.Span, salt, info, bytes);
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
                    DeriveBytesCore(sharedSecret.Span, salt, info, seed);
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

        private protected abstract void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes);
    }
}
