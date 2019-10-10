using System;
using NSec.Experimental;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class ChaCha20Tests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = StreamCipherAlgorithm.ChaCha20;

            Assert.Equal(32, a.KeySize);
            Assert.Equal(12, a.NonceSize);
        }

        #endregion
    }
}
