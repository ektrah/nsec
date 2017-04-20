using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
    //
    //  A cryptographic hash algorithm
    //
    //  Possible Instances
    //
    //      | Algorithm | Reference       | Customization | Hash Size |
    //      | --------- | --------------- | ------------- | --------- |
    //      | BLAKE2b   | RFC 7693        | no            | 1..64     |
    //      | SHA-256   | RFC 6234        | no            | 32        |
    //      | SHA-512   | RFC 6234        | no            | 64        |
    //      | SHA3-256  | NIST FIPS 202   | no            | 32        |
    //      | SHA3-512  | NIST FIPS 202   | no            | 64        |
    //      | SHAKE128  | NIST FIPS 202   | no            | any       |
    //      | SHAKE256  | NIST FIPS 202   | no            | any       |
    //      | cSHAKE128 | NIST SP 800-185 | yes           | any       |
    //      | cSHAKE256 | NIST SP 800-185 | yes           | any       |
    //
    public abstract class HashAlgorithm : Algorithm
    {
        private readonly int _defaultHashSize;
        private readonly int _maxHashSize;
        private readonly int _minHashSize;

        internal HashAlgorithm(
            int minHashSize,
            int defaultHashSize,
            int maxHashSize)
        {
            Debug.Assert(minHashSize >= 0);
            Debug.Assert(defaultHashSize > 0);
            Debug.Assert(defaultHashSize >= minHashSize);
            Debug.Assert(maxHashSize >= defaultHashSize);

            _minHashSize = minHashSize;
            _defaultHashSize = defaultHashSize;
            _maxHashSize = maxHashSize;
        }

        public int DefaultHashSize => _defaultHashSize;

        public int MaxHashSize => _maxHashSize;

        public int MinHashSize => _minHashSize;

        public byte[] Hash(
            ReadOnlySpan<byte> data)
        {
            byte[] hash = new byte[_defaultHashSize];
            HashCore(data, hash);
            return hash;
        }

        public byte[] Hash(
            ReadOnlySpan<byte> data,
            int hashSize)
        {
            if (hashSize < _minHashSize || hashSize > _maxHashSize)
                throw Error.ArgumentOutOfRange_HashSize(nameof(hashSize), hashSize.ToString(), _minHashSize.ToString(), _maxHashSize.ToString());
            if (hashSize == 0)
                return new byte[0];

            byte[] hash = new byte[hashSize];
            HashCore(data, hash);
            return hash;
        }

        public void Hash(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            if (hash.Length < _minHashSize || hash.Length > _maxHashSize)
                throw Error.Argument_HashSize(nameof(hash), hash.Length.ToString(), _minHashSize.ToString(), _maxHashSize.ToString());
            if (hash.IsEmpty)
                return;

            HashCore(data, hash);
        }

        public bool TryVerify(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            if (hash.Length < _minHashSize || hash.Length > _maxHashSize)
                return false;

            return TryVerifyCore(data, hash);
        }

        public void Verify(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            if (hash.Length < _minHashSize || hash.Length > _maxHashSize)
                throw Error.Argument_HashSize(nameof(hash), hash.Length.ToString(), _minHashSize.ToString(), _maxHashSize.ToString());

            if (!TryVerifyCore(data, hash))
            {
                throw Error.Cryptographic_VerificationFailed();
            }
        }

        internal abstract void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash);

        internal abstract bool TryVerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash);
    }
}
