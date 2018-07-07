using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class HashAlgorithmTests
    {
        public static readonly TheoryData<HashAlgorithm> HashAlgorithms = Registry.HashAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void Properties(HashAlgorithm a)
        {
            Assert.True(a.HashSize > 0);
        }

        #endregion

        #region Hash #1

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashSuccess(HashAlgorithm a)
        {
            var data = Utilities.RandomBytes.Slice(0, 100);

            var expected = a.Hash(data);
            var actual = a.Hash(data);

            Assert.NotNull(actual);
            Assert.Equal(a.HashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Hash #3

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanTooSmall(HashAlgorithm a)
        {
            Assert.Throws<ArgumentException>("hash", () => a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.HashSize - 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanTooLarge(HashAlgorithm a)
        {
            Assert.Throws<ArgumentException>("hash", () => a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.HashSize + 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanSuccess(HashAlgorithm a)
        {
            var data = Utilities.RandomBytes.Slice(0, 100);

            var expected = new byte[a.HashSize];
            var actual = new byte[a.HashSize];

            a.Hash(data, expected);
            a.Hash(data, actual);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanOverlapping(HashAlgorithm a)
        {
            var data = Utilities.RandomBytes.Slice(0, 100).ToArray();

            var expected = new byte[a.HashSize];
            var actual = data.AsSpan(0, a.HashSize);

            a.Hash(data, expected);
            a.Hash(data, actual);
            Assert.Equal(expected, actual.ToArray());
        }

        #endregion

        #region Verify

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void VerifyWithSpanTooSmall(HashAlgorithm a)
        {
            Assert.False(a.Verify(ReadOnlySpan<byte>.Empty, new byte[a.HashSize - 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void VerifyWithSpanTooLarge(HashAlgorithm a)
        {
            Assert.False(a.Verify(ReadOnlySpan<byte>.Empty, new byte[a.HashSize + 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void VerifyWithSpanSuccess(HashAlgorithm a)
        {
            var d = ReadOnlySpan<byte>.Empty;

            var hash = a.Hash(d);

            Assert.True(a.Verify(d, hash));
        }

        #endregion
    }
}
