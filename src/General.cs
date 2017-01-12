using System;
using System.Text;
using NSec.Cryptography;
using Xunit;

namespace Snippets
{
    public static class General
    {
        [Fact]
        public static void ReadmeExample()
        {
            #region README Example

            // select the Ed25519 signature algorithm
            var algorithm = new Ed25519();

            // create a new key pair
            using (var key = new Key(algorithm))
            {
                // generate some data to be signed
                var data = Encoding.UTF8.GetBytes("Hello World");

                // sign the data with the private key
                var signature = algorithm.Sign(key, data);

                // verify the signature and the data with the public key
                algorithm.Verify(key.PublicKey, data, signature);
            }

            #endregion
        }
    }
}
