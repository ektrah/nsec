using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Blake2bTests
    {
        #region Properties

        [Fact]
        public static void Properties256()
        {
            var a = HashAlgorithm.Blake2b_256;

            Assert.Equal(32, a.HashSize);
        }

        [Fact]
        public static void Properties512()
        {
            var a = HashAlgorithm.Blake2b_512;

            Assert.Equal(64, a.HashSize);
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
