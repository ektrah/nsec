using System;
using System.Text;
using NSec.Cryptography;
using NSec.Experimental;
using Xunit;

namespace NSec.Tests.Examples
{
    public static class Incremental
    {
        [Fact]
        public static void Hash()
        {
            #region Incremental Hash

            // select the BLAKE2b-256 algorithm
            var algorithm = HashAlgorithm.Blake2b_256;

            // initialize the state with the algorithm
            IncrementalHash.Initialize(algorithm, out var state);

            // append some data to the state
            var items = new[]
            {
                "It is a period of civil war. ",
                "Rebel spaceships, striking ",
                "from a hidden base, have won ",
                "their first victory against ",
                "the evil Galactic Empire."
            };
            foreach (var item in items)
            {
                IncrementalHash.Update(ref state, Encoding.UTF8.GetBytes(item));
            }

            // finalize the computation and get the result
            var hash = IncrementalHash.Finalize(ref state);

            Assert.Equal(algorithm.Hash(Encoding.UTF8.GetBytes(string.Concat(items))), hash);

            #endregion
        }

        [Fact]
        public static void Mac()
        {
            #region Incremental MAC

            // select the BLAKE2b-256 algorithm
            var algorithm = MacAlgorithm.Blake2b_256;

            // create a new key
            using (var key = new Key(algorithm))
            {
                // initialize the state with the key
                IncrementalMac.Initialize(key, out var state);

                // append some data to the state
                var items = new[]
                {
                    "It is a dark time for the ",
                    "Rebellion. Although the Death ",
                    "Star has been destroyed, ",
                    "Imperial troops have driven the ",
                    "Rebel forces from their hidden ",
                    "base and pursued them across ",
                    "the galaxy."
                };
                foreach (var item in items)
                {
                    IncrementalMac.Update(ref state, Encoding.UTF8.GetBytes(item));
                }

                // finalize the computation and get the result
                var mac = IncrementalMac.Finalize(ref state);

                Assert.Equal(algorithm.Mac(key, Encoding.UTF8.GetBytes(string.Concat(items))), mac);
            }

            #endregion
        }
    }
}
