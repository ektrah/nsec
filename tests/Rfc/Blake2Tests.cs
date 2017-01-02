using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Rfc
{
    public static class Blake2Tests
    {
        public static readonly TheoryData<string, string> Rfc7693TestVectors = new TheoryData<string, string>
        {
            { "616263", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923" },
        };

        [Theory]
        [MemberData(nameof(Rfc7693TestVectors))]
        public static void TestRfc7693(string msg, string hash)
        {
            var a = new Blake2();

            var expected = hash.DecodeHex();
            var actual = a.Hash(msg.DecodeHex(), expected.Length);

            Assert.Equal(expected, actual);
        }
    }
}
