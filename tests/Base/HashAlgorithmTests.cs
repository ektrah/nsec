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

            Assert.True(a.HashSize > 0);
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
            Assert.Equal(a.HashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Hash #3

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanTooSmall(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("hash", () => a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.HashSize - 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanTooLarge(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("hash", () => a.Hash(ReadOnlySpan<byte>.Empty, new byte[a.HashSize + 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void HashWithSpanSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var data = Utilities.RandomBytes.Slice(0, 100);

            var expected = new byte[a.HashSize];
            var actual = new byte[a.HashSize];

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

            var expected = new byte[a.HashSize];
            var actual = data.AsSpan(0, a.HashSize);

            a.Hash(data, expected);
            a.Hash(data, actual);
            Assert.Equal(expected, actual.ToArray());
        }

        #endregion

        #region TryVerify

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void TryVerifyWithSpanTooSmall(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.False(a.TryVerify(ReadOnlySpan<byte>.Empty, new byte[a.HashSize - 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void TryVerifyWithSpanTooLarge(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.False(a.TryVerify(ReadOnlySpan<byte>.Empty, new byte[a.HashSize + 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void TryVerifyWithSpanSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var d = ReadOnlySpan<byte>.Empty;

            var hash = a.Hash(d);

            Assert.True(a.TryVerify(d, hash));
        }

        #endregion

        #region Verify

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void VerifyWithSpanTooSmall(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<CryptographicException>(() => a.Verify(ReadOnlySpan<byte>.Empty, new byte[a.HashSize - 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void VerifyWithSpanTooLarge(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<CryptographicException>(() => a.Verify(ReadOnlySpan<byte>.Empty, new byte[a.HashSize + 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void VerifyWithSpanSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var d = ReadOnlySpan<byte>.Empty;

            var hash = a.Hash(d);

            a.Verify(d, hash);
        }

        #endregion
    }
}
