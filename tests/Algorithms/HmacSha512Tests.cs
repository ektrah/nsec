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

            Assert.Equal(64, a.MinKeySize);
            Assert.Equal(64, a.DefaultKeySize);
            Assert.Equal(int.MaxValue, a.MaxKeySize);

            Assert.Equal(16, a.MinMacSize);
            Assert.Equal(64, a.DefaultMacSize);
            Assert.Equal(64, a.MaxMacSize);
        }

        #endregion
    }
}
