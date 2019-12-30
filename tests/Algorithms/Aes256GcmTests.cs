using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Aes256GcmTests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = AeadAlgorithm.Aes256Gcm;

            Assert.Equal(32, a.KeySize);
            Assert.Equal(12, a.NonceSize);
            Assert.Equal(16, a.TagSize);
        }

        [Fact]
        public static void IsSupported()
        {
            Assert.InRange(Aes256Gcm.IsSupported, false, true);
        }

        #endregion
    }
}
