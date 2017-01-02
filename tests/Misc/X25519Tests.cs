using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.More
{
    public static class X25519Tests
    {
        public static readonly TheoryData<string, string> TestVectorsAllZeros = new TheoryData<string, string>
        {
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "0000000000000000000000000000000000000000000000000000000000000000" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "0100000000000000000000000000000000000000000000000000000000000000" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" },
        };

        public static readonly TheoryData<string, string, string> TestVectorsNotAllZeros = new TheoryData<string, string, string>
        {
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", "7ce548bc4919008436244d2da7a9906528fe3a6d278047654bd32d8acde9707b" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7", "e17902e989a034acdf7248260e2c94cdaf2fe1e72aaac7024a128058b6189939" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ea6e6ddf0685c31e152d5818441ac9ac8db1a01f3d6cb5041b07443a901e7145" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "845ddce7b3a9b3ee01a2f1fd4282ad293310f7a232cbc5459fb35d94bccc9d05" },
            { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "6989e2cb1cea159acf121b0af6bf77493189c9bd32c2dac71669b540f9488247" },
        };

        [Theory]
        [MemberData(nameof(TestVectorsAllZeros))]
        public static void TestAllZeros(string privateKey, string publicKey)
        {
            var a = new X25519();

            var pk = PublicKey.Import(a, publicKey.DecodeHex(), KeyBlobFormat.RawPublicKey);

            using (var k = Key.Import(a, privateKey.DecodeHex(), KeyBlobFormat.RawPrivateKey))
            {
                Assert.False(a.TryAgree(k, pk, out SharedSecret s));
                Assert.Null(s);

                Assert.Throws<CryptographicException>(() => a.Agree(k, pk));
            }
        }

        [Theory]
        [MemberData(nameof(TestVectorsNotAllZeros))]
        public static void TestNotAllZeros(string privateKey, string publicKey, string sharedSecret)
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
