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
            Assert.Equal(64, HmacSha512.MinKeySize);
            Assert.Equal(64, HmacSha512.MaxKeySize);
            Assert.Equal(64, HmacSha512.MinMacSize);
            Assert.Equal(64, HmacSha512.MaxMacSize);
        }

        [Fact]
        public static void Properties512()
        {
            var a = MacAlgorithm.HmacSha512;

            Assert.Equal(64, a.KeySize);
            Assert.Equal(64, a.MacSize);
        }

        #endregion
    }
}
