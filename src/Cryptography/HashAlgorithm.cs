using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
    //
    //  A cryptographic hash algorithm
    //
    //  Examples
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
            Debug.Assert(minHashSize > 0);
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
            if (hashSize < _minHashSize)
                throw new ArgumentOutOfRangeException(nameof(hashSize));
            if (hashSize > _maxHashSize)
                throw new ArgumentOutOfRangeException(nameof(hashSize));

            byte[] hash = new byte[hashSize];
            HashCore(data, hash);
            return hash;
        }

        public void Hash(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            if (hash.Length < _minHashSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(hash));
            if (hash.Length > _maxHashSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(hash));

            HashCore(data, hash);
        }

        internal abstract void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash);
    }
}
