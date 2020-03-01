using System;
using NSec.Cryptography;
using NSec.Experimental.Sodium;
using Xunit;

namespace NSec.Tests.Rfc
{
    public static class XChaCha20Poly1305Tests
    {
        // draft-irtf-cfrg-xchacha-03
        public static readonly TheoryData<string[]> TestVectors = new TheoryData<string[]>
        {
            // Appendix A.1
            new string[] { "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e", "50515253c0c1c2c3c4c5c6c7", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "404142434445464748494a4b4c4d4e4f5051525354555657", "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e", "c0875924c1c7987947deafd8780acf49" },
        };

        [Theory]
        [MemberData(nameof(TestVectors))]
        public static void Test(string[] testVector)
        {
            var plaintext = testVector[0];
            var aad = testVector[1];
            var key = testVector[2];
            var nonce = testVector[3];
            var ciphertext = testVector[4];
            var tag = testVector[5];

            var a = new XChaCha20Poly1305();

            using var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey);

            var b = a.Encrypt(k, new Nonce(nonce.DecodeHex(), 0), aad.DecodeHex(), plaintext.DecodeHex());
            Assert.Equal((ciphertext + tag).DecodeHex(), b);

            Assert.True(a.Decrypt(k, new Nonce(nonce.DecodeHex(), 0), aad.DecodeHex(), b, out var r));
            Assert.Equal(plaintext.DecodeHex(), r);
        }
    }
}
