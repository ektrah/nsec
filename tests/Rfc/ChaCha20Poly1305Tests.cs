using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class ChaCha20Poly1305Tests
    {
        public static readonly TheoryData<string[]> Rfc7539TestVectors = new TheoryData<string[]>
        {
            new string[] { "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e", "50515253c0c1c2c3c4c5c6c7", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "07000000" + "4041424344454647", "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116", "1ae10b594f09e26a7e902ecbd0600691" },
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

            var a = new ChaCha20Poly1305();

            using (var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey))
            {
                var b = a.Encrypt(k, nonce.DecodeHex(), aad.DecodeHex(), plaintext.DecodeHex());
                Assert.Equal((ciphertext + tag).DecodeHex(), b);

                var r = a.Decrypt(k, nonce.DecodeHex(), aad.DecodeHex(), b);
                Assert.Equal(plaintext.DecodeHex(), r);
            }
        }
    }
}
