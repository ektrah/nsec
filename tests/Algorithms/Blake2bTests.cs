using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Blake2bTests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            Assert.Equal(32, Blake2b.MinHashSize);
            Assert.Equal(64, Blake2b.MaxHashSize);

            Assert.Equal(32, HashAlgorithm.Blake2b_256.HashSize);

            Assert.Equal(64, HashAlgorithm.Blake2b_512.HashSize);
        }

        [Theory]
        [InlineData(256 / 8)]
        [InlineData(384 / 8)]
        [InlineData(512 / 8)]
        public static void PropertiesContructed(int hashSize)
        {
            var a = new Blake2b(hashSize);

            Assert.Equal(hashSize, a.HashSize);
        }

        #endregion

        #region Ctor #2

        [Fact]
        public static void CtorWithHashSizeTooSmall()
        {
            Assert.Throws<ArgumentOutOfRangeException>("hashSize", () => new Blake2b(32 - 1));
        }

        [Fact]
        public static void CtorWithHashSizeTooLarge()
        {
            Assert.Throws<ArgumentOutOfRangeException>("hashSize", () => new Blake2b(64 + 1));
        }

        #endregion
    }
}
