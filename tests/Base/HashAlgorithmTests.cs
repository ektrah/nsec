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

            Assert.True(a.MinHashSize > 0);
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

            var b = a.Hash(ReadOnlySpan<byte>.Empty);

            Assert.NotNull(b);
            Assert.Equal(a.DefaultHashSize, b.Length);
        }

        #endregion

        #region Hash #2

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSizeTooSmall(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentOutOfRangeException>("hashSize", () => a.Hash(ReadOnlySpan<byte>.Empty, a.MinHashSize - 1));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSizeTooLarge(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentOutOfRangeException>("hashSize", () => a.Hash(ReadOnlySpan<byte>.Empty, a.MaxHashSize + 1));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSizeSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var b = a.Hash(ReadOnlySpan<byte>.Empty, a.MaxHashSize);

            Assert.NotNull(b);
            Assert.Equal(a.MaxHashSize, b.Length);
        }

        #endregion

        #region Hash #3

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanTooSmall(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("hash", () => a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.MinHashSize - 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanTooLarge(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("hash", () => a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.MaxHashSize + 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.MaxHashSize]);
        }

        #endregion
    }
}
