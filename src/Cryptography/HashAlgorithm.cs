using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
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
