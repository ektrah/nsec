using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Ed25519Tests
    {
        [Fact]
        public static void Properties()
        {
            var a = new Ed25519();

            Assert.Equal(32, a.PublicKeySize);
            Assert.Equal(32, a.PrivateKeySize);
            Assert.Equal(64, a.SignatureSize);
        }
    }
}
