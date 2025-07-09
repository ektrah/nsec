using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Rfc
{
    public static class ChaCha20Poly1305Tests
    {
        public static readonly TheoryData<string[]> Rfc8439TestVectors =
        [
            // Section 2.8.2
            new string[] {
                "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
                "50515253c0c1c2c3c4c5c6c7",
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "07000000" + "4041424344454647",
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
                "1ae10b594f09e26a7e902ecbd0600691"
            },
            // Appendix A.5
            new string[] {
                "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
                "f33388860000000000004e91",
                "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
                "000000000102030405060708",
                "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b",
                "eead9d67890cbb22392336fea1851f38"
            },
        ];

        public static readonly TheoryData<string[]> Rfc7634TestVectors =
        [
            // Appendix A.
            new string[] {
                "45000054a6f200004001e778c6336405c000020508005b7a3a080000553bec100007362708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363701020204",
                "0102030400000005",
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "a0a1a2a31011121314151617",
                "24039428b97f417e3c13753a4f05087b67c352e6a7fab1b982d466ef407ae5c614ee8099d52844eb61aa95dfab4c02f72aa71e7c4c4f64c9befe2facc638e8f3cbec163fac469b502773f6fb94e664da9165b82829f641e0",
                "76aaa8266b7fb0f7b11b369907e1ad43"
            },
            // Appendix B.
            new string[] {
                "0000000c000040010000000a00",
                "c0c1c2c3c4c5c6c7d0d1d2d3d4d5d6d72e202500000000090000004529000029",
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "a0a1a2a31011121314151617",
                "610394701f8d017f7c12924889",
                "6b71bfe25236efd7cdc67066906315b2"
            },
        ];

        [Theory]
        [MemberData(nameof(Rfc8439TestVectors))]
        [MemberData(nameof(Rfc7634TestVectors))]
        public static void Test(string[] testVector)
        {
            var plaintext = testVector[0];
            var aad = testVector[1];
            var key = testVector[2];
            var nonce = testVector[3];
            var ciphertext = testVector[4];
            var tag = testVector[5];

            var a = AeadAlgorithm.ChaCha20Poly1305;

            using var k = Key.Import(a, Convert.FromHexString(key), KeyBlobFormat.RawSymmetricKey);

            var ct = a.Encrypt(k, Convert.FromHexString(nonce), Convert.FromHexString(aad), Convert.FromHexString(plaintext));
            Assert.Equal(Convert.FromHexString(ciphertext + tag), ct);

            var pt = a.Decrypt(k, Convert.FromHexString(nonce), Convert.FromHexString(aad), ct);
            Assert.Equal(Convert.FromHexString(plaintext), pt);
        }
    }
}
