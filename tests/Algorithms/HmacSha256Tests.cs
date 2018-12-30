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
            var a = new HmacSha256();

            Assert.Equal(32, HmacSha256.MinKeySize);
            Assert.Equal(32, HmacSha256.MaxKeySize);
            Assert.Equal(16, HmacSha256.MinMacSize);
            Assert.Equal(32, HmacSha256.MaxMacSize);

            Assert.Equal(32, a.KeySize);
            Assert.Equal(32, a.MacSize);

            Assert.Equal(32, MacAlgorithm.HmacSha256_128.KeySize);
            Assert.Equal(16, MacAlgorithm.HmacSha256_128.MacSize);

            Assert.Equal(32, MacAlgorithm.HmacSha256.KeySize);
            Assert.Equal(32, MacAlgorithm.HmacSha256.MacSize);
        }

        #endregion
    }
}
