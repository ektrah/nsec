using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class HashAlgorithmTests
    {
        public static readonly TheoryData<Type> HashAlgorithms = Registry.HashAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.MinHashSize >= 0);
            Assert.True(a.DefaultHashSize > 0);
            Assert.True(a.DefaultHashSize >= a.MinHashSize);
            Assert.True(a.MaxHashSize >= a.DefaultHashSize);
        }

        #endregion

        #region Hash #1

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var data = Utilities.RandomBytes.Slice(0, 100);

            var expected = a.Hash(data);
            var actual = a.Hash(data);

            Assert.NotNull(actual);
            Assert.Equal(a.DefaultHashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Hash #2

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSizeTooSmall(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinHashSize > 0)
            {
                Assert.Throws<ArgumentOutOfRangeException>("hashSize", () => a.Hash(ReadOnlySpan<byte>.Empty, a.MinHashSize - 1));
            }
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSizeTooLarge(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MaxHashSize < int.MaxValue)
            {
                Assert.Throws<ArgumentOutOfRangeException>("hashSize", () => a.Hash(ReadOnlySpan<byte>.Empty, a.MaxHashSize + 1));
            }
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSizeSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var data = Utilities.RandomBytes.Slice(0, 100);

            var expected = a.Hash(data, 32);
            var actual = a.Hash(data, 32);

            Assert.NotNull(actual);
            Assert.Equal(32, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Hash #3

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanTooSmall(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinHashSize > 0)
            {
                Assert.Throws<ArgumentException>("hash", () => a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.MinHashSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanTooLarge(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MaxHashSize < int.MaxValue)
            {
                Assert.Throws<ArgumentException>("hash", () => a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.MaxHashSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var data = Utilities.RandomBytes.Slice(0, 100);

            var expected = new byte[a.DefaultHashSize];
            var actual = new byte[a.DefaultHashSize];

            a.Hash(data, expected);
            a.Hash(data, actual);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanOverlapping(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var data = Utilities.RandomBytes.Slice(0, 100).ToArray();

            var expected = new byte[a.DefaultHashSize];
            var actual = data.AsSpan(0, a.DefaultHashSize);

            a.Hash(data, expected);
            a.Hash(data, actual);
            Assert.Equal(expected, actual.ToArray());
        }

        #endregion
    }
}
