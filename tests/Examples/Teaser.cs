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
            using (var key = new Key(algorithm))
            {
                // generate some data to be signed
                var data = Encoding.UTF8.GetBytes("Use the Force, Luke!");

                // sign the data with the private key
                var signature = algorithm.Sign(key, data);

                // verify data and signature with the public key
                algorithm.Verify(key.PublicKey, data, signature);
            }

            #endregion
        }
    }
}
