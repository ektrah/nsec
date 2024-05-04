using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Aegis256Tests
    {
        public static readonly TheoryData<int> PlaintextLengths = Utilities.Primes;

        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = AeadAlgorithm.Aegis256;

            Assert.Equal(32, a.KeySize);
            Assert.Equal(32, a.NonceSize);
            Assert.Equal(32, a.TagSize);
        }

        #endregion

        #region Encrypt/Decrypt

        [Theory]
        [MemberData(nameof(PlaintextLengths))]
        public static void EncryptDecrypt(int length)
        {
            var a = AeadAlgorithm.Aegis256;

            using var k = new Key(a);
            var n = Utilities.RandomBytes[..a.NonceSize];
            var ad = Utilities.RandomBytes[..100];

            var expected = Utilities.RandomBytes[..length].ToArray();

            var ciphertext = a.Encrypt(k, n, ad, expected);
            Assert.NotNull(ciphertext);
            Assert.Equal(length + a.TagSize, ciphertext.Length);

            var actual = a.Decrypt(k, n, ad, ciphertext);
            Assert.NotNull(actual);
            Assert.Equal(expected, actual);
        }

        #endregion
    }
}
