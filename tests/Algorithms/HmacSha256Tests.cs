using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class HmacSha256Tests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            Assert.Equal(32, HmacSha256.MinKeySize);
            Assert.Equal(32, HmacSha256.MaxKeySize);
            Assert.Equal(32, HmacSha256.MinMacSize);
            Assert.Equal(32, HmacSha256.MaxMacSize);
        }

        [Fact]
        public static void Properties256()
        {
            var a = MacAlgorithm.HmacSha256;

            Assert.Equal(32, a.KeySize);
            Assert.Equal(32, a.MacSize);
        }

        #endregion
    }
}
