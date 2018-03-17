using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Ed25519Tests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = SignatureAlgorithm.Ed25519;

            Assert.Equal(32, a.PublicKeySize);
            Assert.Equal(32, a.PrivateKeySize);
            Assert.Equal(64, a.SignatureSize);
        }

        #endregion
    }
}
