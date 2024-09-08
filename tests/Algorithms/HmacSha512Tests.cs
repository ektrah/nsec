using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class HmacSha512Tests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = new HmacSha512();

            Assert.Equal(32, HmacSha512.MinKeySize);
            Assert.Equal(64, HmacSha512.MaxKeySize);
            Assert.Equal(16, HmacSha512.MinMacSize);
            Assert.Equal(64, HmacSha512.MaxMacSize);

            Assert.Equal(64, a.KeySize);
            Assert.Equal(64, a.MacSize);

            Assert.Equal(64, MacAlgorithm.HmacSha512_256.KeySize);
            Assert.Equal(32, MacAlgorithm.HmacSha512_256.MacSize);

            Assert.Equal(64, MacAlgorithm.HmacSha512.KeySize);
            Assert.Equal(64, MacAlgorithm.HmacSha512.MacSize);
        }

        #endregion
    }
}
