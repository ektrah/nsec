using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Rfc
{
    public static class X25519Tests
    {
        public static readonly TheoryData<string, string, string> Rfc7748TestVectors = new TheoryData<string, string, string>
        {
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" },
            { "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957" },
        };

        [Theory]
        [MemberData(nameof(Rfc7748TestVectors))]
        public static void Test(string privateKey, string publicKey, string sharedSecret)
        {
            var a = new X25519();
            var kdf = new HkdfSha256();

            using (var k = Key.Import(a, privateKey.DecodeHex(), KeyBlobFormat.RawPrivateKey))
            using (var sharedSecretExpected = SharedSecret.Import(sharedSecret.DecodeHex()))
            using (var sharedSecretActual = a.Agree(k, PublicKey.Import(a, publicKey.DecodeHex(), KeyBlobFormat.RawPublicKey)))
            {
                var expected = kdf.Extract(sharedSecretExpected, ReadOnlySpan<byte>.Empty);
                var actual = kdf.Extract(sharedSecretActual, ReadOnlySpan<byte>.Empty);

                Assert.Equal(expected, actual);
            }
        }
    }
}
