using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Core
{
    public class KeyConverterTests
    {
        [Fact]
        public void TestConvertPrivateKey()
        {
            var a = KeyAgreementAlgorithm.X25519;

            using var e = Key.Create(SignatureAlgorithm.Ed25519);

            using var k = KeyConverter.ConvertPrivateKey(e, a);

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

            var p = KeyConverter.ConvertPublicKey(e.PublicKey, a);

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

            using var x25519priv = KeyConverter.ConvertPrivateKey(k, a);

            var x25519pub = KeyConverter.ConvertPublicKey(k.PublicKey, a);

            Assert.Equal(x25519priv.PublicKey, x25519pub);
        }
    }
}
