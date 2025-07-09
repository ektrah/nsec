using System;
using NSec.Cryptography;
using NSec.Experimental;
using Xunit;

namespace NSec.Tests.Rfc
{
    public class ChaCha20Tests
    {
        public static readonly TheoryData<string[]> Rfc8439TestVectors =
        [
            // Appendix A.1 Test Vector #1
            new string[] {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
                "0"
            },
            // Appendix A.1 Test Vector #2
            new string[] {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
                "1"
            },
            // Appendix A.1 Test Vector #3
            new string[] {
                "0000000000000000000000000000000000000000000000000000000000000001",
                "000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
                "1"
            },
            // Appendix A.1 Test Vector #4
            new string[] {
                "00ff000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
                "2"
            },
            // Appendix A.1 Test Vector #5
            new string[] {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000002",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
                "0"
            },
        ];

        [Theory]
        [MemberData(nameof(Rfc8439TestVectors))]
        public static void Test(string[] testVector)
        {
            var key = testVector[0];
            var nonce = testVector[1];
            var plaintext = testVector[2];
            var ciphertext = testVector[3];
            var initialBlockCounter = uint.Parse(testVector[4]);

            var a = StreamCipherAlgorithm.ChaCha20;

            using var k = Key.Import(a, Convert.FromHexString(key), KeyBlobFormat.RawSymmetricKey);

            var b = a.XOrIC(k, Convert.FromHexString(nonce), Convert.FromHexString(plaintext), initialBlockCounter);

            Assert.Equal(Convert.FromHexString(ciphertext), b);
        }
    }
}
