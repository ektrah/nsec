using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class X25519Tests
    {
        public static readonly TheoryData<string, string, string> Rfc7748TestVectors = Rfc.X25519Tests.Rfc7748TestVectors;

        [Theory]
        [MemberData(nameof(Rfc7748TestVectors))]
        public static void BitMaskedAgree(string privateKey, string publicKey, string sharedSecret)
        {
            var a = new X25519();
            var kdf = new HkdfSha256();

            var pk1 = publicKey.DecodeHex();
            var pk2 = publicKey.DecodeHex();

            pk1[pk1.Length - 1] &= 0x7F;
            pk2[pk2.Length - 1] |= 0x80;

            using (var k = Key.Import(a, privateKey.DecodeHex(), KeyBlobFormat.RawPrivateKey))
            using (var sharedSecretExpected = SharedSecret.Import(sharedSecret.DecodeHex()))
            using (var sharedSecretActual1 = a.Agree(k, PublicKey.Import(a, pk1, KeyBlobFormat.RawPublicKey)))
            using (var sharedSecretActual2 = a.Agree(k, PublicKey.Import(a, pk2, KeyBlobFormat.RawPublicKey)))
            {
                var expected = kdf.Extract(sharedSecretExpected, ReadOnlySpan<byte>.Empty);
                var actual1 = kdf.Extract(sharedSecretActual1, ReadOnlySpan<byte>.Empty);
                var actual2 = kdf.Extract(sharedSecretActual2, ReadOnlySpan<byte>.Empty);

                Assert.Equal(expected, actual1);
                Assert.Equal(expected, actual2);
            }
        }

        [Theory]
        [MemberData(nameof(Rfc7748TestVectors))]
        public static void BitMaskedEquals(string privateKey, string publicKey, string sharedSecret)
        {
            var a = new X25519();

            var pk1 = publicKey.DecodeHex();
            var pk2 = publicKey.DecodeHex();

            pk1[pk1.Length - 1] &= 0x7F;
            pk2[pk2.Length - 1] |= 0x80;

            var p1 = PublicKey.Import(a, pk1, KeyBlobFormat.RawPublicKey);
            var p2 = PublicKey.Import(a, pk2, KeyBlobFormat.RawPublicKey);

            Assert.True(p1.Equals(p2));
        }
    }
}
