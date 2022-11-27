using System;
using NSec.Cryptography;
using NSec.Experimental.PasswordBased;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Argon2iTests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var expected = new Argon2Parameters { DegreeOfParallelism = 1, MemorySize = 1 << 12, NumberOfPasses = 3 }; // intentionally weak parameters for unit testing

            var a = new Argon2i(expected);
            a.GetParameters(out var actual);

            Assert.Equal(16, a.MaxSaltSize);
            Assert.Equal(16, a.MinSaltSize);
            Assert.Equal(int.MaxValue, a.MaxCount);

            Assert.Equal(expected.DegreeOfParallelism, actual.DegreeOfParallelism);
            Assert.Equal(expected.MemorySize, actual.MemorySize);
            Assert.Equal(expected.NumberOfPasses, actual.NumberOfPasses);
        }

        #endregion
    }
}
