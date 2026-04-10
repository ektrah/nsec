using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Sha3_256Tests
    {
        private const string s_hashOfEmpty = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = new Sha3_256();

            Assert.Equal(32, Sha3_256.MinHashSize);
            Assert.Equal(32, Sha3_256.MaxHashSize);

            Assert.Equal(32, a.HashSize);

            Assert.Equal(32, HashAlgorithm.Sha3_256.HashSize);
        }

        #endregion

        #region Hash #1

        [Fact]
        public static void HashEmpty()
        {
            var a = HashAlgorithm.Sha3_256;

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
            var a = HashAlgorithm.Sha3_256;

            var expected = Convert.FromHexString(s_hashOfEmpty);
            var actual = new byte[expected.Length];

            a.Hash([], actual);
            Assert.Equal(expected, actual);
        }

        #endregion
    }
}
