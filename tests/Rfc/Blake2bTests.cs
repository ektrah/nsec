using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Rfc
{
    public static class Blake2Tests
    {
        public static readonly TheoryData<string, string> Rfc7693TestVectors = new()
        {
            { "616263", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923" },
        };

        [Theory]
        [MemberData(nameof(Rfc7693TestVectors))]
        public static void Test(string msg, string hash)
        {
            var a = HashAlgorithm.Blake2b_512;

            var expected = Convert.FromHexString(hash);
            var actual = a.Hash(Convert.FromHexString(msg));

            Assert.Equal(expected, actual);
        }
    }
}
