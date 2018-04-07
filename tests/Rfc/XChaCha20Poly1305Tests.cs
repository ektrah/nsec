using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Rfc
{
    public static class XChaCha20Poly1305Tests
    {
        public static readonly TheoryData<string[]> Rfc7539TestVectors = new TheoryData<string[]>
        {
            new string[]
            {
                "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
                "50515253c0c1c2c3c4c5c6c7",
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "07000000" + "404142434445464748494a4b0000000000000000",
                "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8b89ad929530a1bb3ab5e69f24c7f6070c8f840c9abb4f69fbfc8a7ff5126faeebbb55805ee9c1cf2ce5a57263287aec5780f04ec324c3514122cfc3231fc1a8b718a62863730a2702bb76366116bed09e0fd",
                "5c6d84b6b0c1abaf249d5dd0f7f5a7ea"
            },
        };

        [Theory]
        [MemberData(nameof(Rfc7539TestVectors))]
        public static void Test(string[] testVector)
        {
            var plaintext = testVector[0];
            var aad = testVector[1];
            var key = testVector[2];
            var nonce = testVector[3];
            var ciphertext = testVector[4];
            var tag = testVector[5];

            var a = new XChaCha20Poly1305();

            using (var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey))
            {
                var b = a.Encrypt(k, new Nonce(nonce.DecodeHex(), 0), aad.DecodeHex(), plaintext.DecodeHex());
                Assert.Equal((ciphertext + tag).DecodeHex(), b);

                var r = a.Decrypt(k, new Nonce(nonce.DecodeHex(), 0), aad.DecodeHex(), b);
                Assert.Equal(plaintext.DecodeHex(), r);
            }
        }
    }
}
