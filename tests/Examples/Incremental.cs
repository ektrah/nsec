using System;
using System.Text;
using NSec.Cryptography;
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

            // incrementally update the state with some data
            var lines = new[]
            {
                "It is a period of civil war.\n",
                "Rebel spaceships, striking\n",
                "from a hidden base, have won\n",
                "their first victory against\n",
                "the evil Galactic Empire.\n"
            };
            foreach (var line in lines)
            {
                IncrementalHash.Update(ref state, Encoding.UTF8.GetBytes(line));
            }

            // finalize the computation and get the result
            var hash = IncrementalHash.Finalize(ref state);

            #endregion

            Assert.Equal(algorithm.Hash(Encoding.UTF8.GetBytes(string.Concat(lines))), hash);
        }

        [Fact]
        public static void Mac()
        {
            #region Incremental MAC

            // select the BLAKE2b-256 algorithm
            var algorithm = MacAlgorithm.Blake2b_256;

            // create a new key
            using var key = Key.Create(algorithm);

            // initialize the state with the key
            IncrementalMac.Initialize(key, out var state);

            // incrementally update the state with some data
            var lines = new[]
            {
                "It is a dark time for the\n",
                "Rebellion. Although the Death\n",
                "Star has been destroyed,\n",
                "Imperial troops have driven the\n",
                "Rebel forces from their hidden\n",
                "base and pursued them across\n",
                "the galaxy.\n"
            };
            foreach (var line in lines)
            {
                IncrementalMac.Update(ref state, Encoding.UTF8.GetBytes(line));
            }

            // finalize the computation and get the result
            var mac = IncrementalMac.Finalize(ref state);

            #endregion

            Assert.Equal(algorithm.Mac(key, Encoding.UTF8.GetBytes(string.Concat(lines))), mac);
        }
    }
}
