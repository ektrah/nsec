using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class XChaCha20Poly1305Tests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = AeadAlgorithm.XChaCha20Poly1305;

            Assert.Equal(32, a.KeySize);
            Assert.Equal(24, a.NonceSize);
            Assert.Equal(16, a.TagSize);
        }

        #endregion
    }
}
