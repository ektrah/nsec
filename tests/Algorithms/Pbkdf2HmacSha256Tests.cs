using System;
using NSec.Experimental.PasswordBased;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Pbkdf2HmacSha256Tests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var expected = new Pbkdf2Parameters { IterationCount = 10 }; // intentionally weak parameters for unit testing

            var a = new Pbkdf2HmacSha256(expected);
            a.GetParameters(out var actual);

            Assert.Equal(8, a.MaxSaltSize);
            Assert.Equal(8, a.MinSaltSize);
            Assert.Equal(8, a.SaltSize);
            Assert.Equal(int.MaxValue, a.MaxCount);

            Assert.Equal(expected.IterationCount, actual.IterationCount);
        }

        #endregion
    }
}
