using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Aes256GcmTests
    {
        [Fact]
        public static void Properties()
        {
            var a = new Aes256Gcm();

            Assert.Equal(32, a.KeySize);
            Assert.Equal(12, a.NonceSize);
            Assert.Equal(16, a.TagSize);
        }
    }
}
