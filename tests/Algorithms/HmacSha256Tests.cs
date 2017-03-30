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

            Assert.Equal(32, a.MinKeySize);
            Assert.Equal(32, a.DefaultKeySize);
            Assert.Equal(int.MaxValue, a.MaxKeySize);

            Assert.Equal(16, a.MinMacSize);
            Assert.Equal(32, a.DefaultMacSize);
            Assert.Equal(32, a.MaxMacSize);
        }

        #endregion
    }
}
