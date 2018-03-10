using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Sha256Tests
    {
        private static readonly string s_hashOfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = new Sha256();

            Assert.Equal(32, a.HashSize);
        }

        #endregion

        #region Hash #1

        [Fact]
        public static void HashEmpty()
        {
            var a = new Sha256();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = a.Hash(ReadOnlySpan<byte>.Empty);

            Assert.Equal(a.HashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Hash #3

        [Fact]
        public static void HashEmptyWithSpan()
        {
            var a = new Sha256();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = new byte[expected.Length];

            a.Hash(ReadOnlySpan<byte>.Empty, actual);
            Assert.Equal(expected, actual);
        }

        #endregion
    }
}
