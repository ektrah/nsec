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
            var a = HashAlgorithm.Blake2b_256;

            Assert.Equal(32, a.HashSize);
        }

        #endregion
    }
}
