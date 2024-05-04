using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Sha256Tests
    {
        private const string s_hashOfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = new Sha256();

            Assert.Equal(32, Sha256.MinHashSize);
            Assert.Equal(32, Sha256.MaxHashSize);

            Assert.Equal(32, a.HashSize);

            Assert.Equal(32, HashAlgorithm.Sha256.HashSize);
        }

        #endregion

        #region Hash #1

        [Fact]
        public static void HashEmpty()
        {
            var a = HashAlgorithm.Sha256;

            var expected = Convert.FromHexString(s_hashOfEmpty);
            var actual = a.Hash([]);

            Assert.Equal(a.HashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Hash #3

        [Fact]
        public static void HashEmptyWithSpan()
        {
            var a = HashAlgorithm.Sha256;

            var expected = Convert.FromHexString(s_hashOfEmpty);
            var actual = new byte[expected.Length];

            a.Hash([], actual);
            Assert.Equal(expected, actual);
        }

        #endregion
    }
}
