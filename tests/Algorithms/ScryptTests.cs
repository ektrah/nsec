using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class ScryptTests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var expected = new ScryptParameters { Cost = 1 << 11, BlockSize = 5, Parallelization = 1 }; // intentionally weak parameters for unit testing

            var a = PasswordBasedKeyDerivationAlgorithm.Scrypt(expected);
            a.GetParameters(out var actual);

            Assert.Equal(32, a.MaxSaltSize);
            Assert.Equal(32, a.MinSaltSize);
            Assert.Equal(int.MaxValue, a.MaxCount);

            Assert.Equal(expected.Cost, actual.Cost);
            Assert.Equal(expected.BlockSize, actual.BlockSize);
            Assert.Equal(expected.Parallelization, actual.Parallelization);
        }

        #endregion
    }
}
