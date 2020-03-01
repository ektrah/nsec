using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Rfc
{
    public static class HmacSha256Tests
    {
        public static readonly TheoryData<string, string, string> Rfc4231TestVectors = new TheoryData<string, string, string>
        {
            // { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
            // { "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
            // { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" },
            // { "0102030405060708090a0b0c0d0e0f10111213141516171819", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" },
            // { "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "546573742057697468205472756e636174696f6e", "a3b6167473100ee06e0c796c2955552b" },
            // { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
            // { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" },
        };

        public static readonly TheoryData<string, string, string> Rfc4868TestVectors = new TheoryData<string, string, string>
        {
            // Section 2.7.2.1
            { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265", "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7" },
            { "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "167f928588c5cc2eef8e3093caa0e87c9ff566a14794aa61648d81621a2a40c6" },
            { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0" },
            { "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "372efcf9b40b35c2115b1346903d2ef42fced46f0846e7257bb156d3d7b30d3f" },
        };

        [Theory]
        [MemberData(nameof(Rfc4231TestVectors))]
        [MemberData(nameof(Rfc4868TestVectors))]
        public static void Test(string key, string msg, string mac)
        {
            var a = MacAlgorithm.HmacSha256;

            using var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey);
            var m = msg.DecodeHex();

            var expected = mac.DecodeHex();
            var actual = a.Mac(k, m);
            Assert.Equal(expected, actual);

            Assert.True(a.Verify(k, m, expected));
        }
    }
}
