using System;
using System.Text;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Examples
{
    public static class Teaser
    {
        [Fact]
        public static void Example()
        {
            #region Teaser

            // select the Ed25519 signature algorithm
            var algorithm = SignatureAlgorithm.Ed25519;

            // create a new key pair
            using var key = Key.Create(algorithm);

            // generate some data to be signed
            var data = Encoding.UTF8.GetBytes("Use the Force, Luke!");

            // sign the data using the private key
            var signature = algorithm.Sign(key, data);

            // verify the data using the signature and the public key
            if (algorithm.Verify(key.PublicKey, data, signature))
            {
                // verified!
                /*{*//*}*/
            }

            #endregion

            Assert.True(algorithm.Verify(key.PublicKey, data, signature));
        }
    }
}
