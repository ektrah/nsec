using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Rfc
{

    public class ChaCha20Tests
    {
        public static readonly TheoryData<string[]> Rfc8439TestVectors = new TheoryData<string[]>
        {
            new string[] {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                ("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                 "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                 "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                 "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00").Replace(" ", ""),
                ("76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28" +
                 "bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7" +
                 "da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37" +
                 "6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86").Replace(" ", ""),
                "0"
                }
        };

        [Theory]
        [MemberData(nameof(Rfc8439TestVectors))]
        public static void Test(string[] testVector)
        {
            var key = testVector[0];
            var nonce = testVector[1];
            var plaintext = testVector[2];
            var ciphertext = testVector[3];
            var initialBlockCounter = UInt32.Parse(testVector[4]);
            var a = StreamCipherAlgorithm.ChaCha20;
            using (var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey))
            {
                var b = a.XOrIC(k, new Nonce(nonce.DecodeHex(), 0), plaintext.DecodeHex(), initialBlockCounter);
                Assert.Equal(ciphertext.DecodeHex(), b);
            }
        }

    }
}
