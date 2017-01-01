using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class X25519Tests
    {
        [Fact]
        public static void AgreeWithPublicKeyAllZeros()
        {
            var a = new X25519();

            var pk = PublicKey.Import(a, new byte[a.PublicKeySize], KeyBlobFormat.RawPublicKey);

            using (var k = new Key(a))
            {
                Assert.Throws<CryptographicException>(() => a.Agree(k, pk));
            }
        }

        [Fact]
        public static void TryAgreeWithPublicKeyAllZeros()
        {
            var a = new X25519();

            var pk = PublicKey.Import(a, new byte[a.PublicKeySize], KeyBlobFormat.RawPublicKey);

            using (var k = new Key(a))
            {
                Assert.False(a.TryAgree(k, pk, out SharedSecret s));
                Assert.Null(s);
            }
        }
    }
}
