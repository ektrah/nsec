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
                "07000000" + "4041424344454647000000000000000000000000",
                "7C71AA4CF608BA38C4CBC9FFE3A719C6E15A66A65E16EFEB667BDE69AB85B111DE4BB2CE4F52E107D1327D7A7E2C90B476321B60CB4E1B2A08EC956A4CDEDBCB6F4FED35DDB69D765A9B55C010494AF8487DB280B813783A2C81D5BBAF014D52D55B0FE88DD4A11951B0CB81D88605F4F905",
                "AF7302B6D5949433450C5F9F6824710A"
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
