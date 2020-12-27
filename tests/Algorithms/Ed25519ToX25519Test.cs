using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public class Ed25519ToX25519Test
    {
        [Fact]
        public void TestConvertPrivateKey()
        {
            var a = KeyAgreementAlgorithm.X25519;

            using var e = Key.Create(SignatureAlgorithm.Ed25519);

            using var k = Ed25519ToX25519.ConvertPrivateKey(e, a);

            Assert.Same(a, k.Algorithm);

            Assert.True(k.HasPublicKey);
            Assert.NotNull(k.PublicKey);
            Assert.Same(a, k.PublicKey.Algorithm);

            using var k2 = Key.Create(a);
            using var s = a.Agree(k, k2.PublicKey);
        }

        [Fact]
        public void TestConvertPublicKey()
        {
            var a = KeyAgreementAlgorithm.X25519;

            using var e = Key.Create(SignatureAlgorithm.Ed25519);

            var p = Ed25519ToX25519.ConvertPublicKey(e.PublicKey, a);

            Assert.NotNull(p);
            Assert.Same(a, p.Algorithm);

            using var k2 = Key.Create(a);
            using var s = a.Agree(k2, p);
        }

        [Fact]
        public void TestConvertPublicKeyMatch()
        {
            var a = KeyAgreementAlgorithm.X25519;

            using var k = Key.Create(SignatureAlgorithm.Ed25519);

            using var x25519priv = Ed25519ToX25519.ConvertPrivateKey(k, a);
            var expected = x25519priv.Export(KeyBlobFormat.NSecPublicKey);

            var x25519pub = Ed25519ToX25519.ConvertPublicKey(k.PublicKey, a);
            var actual = x25519pub.Export(KeyBlobFormat.NSecPublicKey);

            Assert.Equal(expected, actual);
        }
    }
}
