using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class KeyAgreementAlgorithmTests
    {
        public static readonly TheoryData<KeyAgreementAlgorithm> KeyAgreementAlgorithms = Registry.KeyAgreementAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void Properties(KeyAgreementAlgorithm a)
        {
            Assert.True(a.PublicKeySize > 0);
            Assert.True(a.PrivateKeySize > 0);
            Assert.True(a.SharedSecretSize > 0);
        }

        #endregion

        #region Agree

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithNullKey(KeyAgreementAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("key", () => a.Agree(null!, null!));
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithDisposedKey(KeyAgreementAlgorithm a)
        {
            using var k2 = new Key(a);

            var k1 = new Key(a);
            k1.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.Agree(k1, k2.PublicKey));
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithWrongKey(KeyAgreementAlgorithm a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("key", () => a.Agree(k, null!));
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithNullPublicKey(KeyAgreementAlgorithm a)
        {
            using var k = new Key(a);
            Assert.Same(a, k.Algorithm);

            Assert.Throws<ArgumentNullException>("otherPartyPublicKey", () => a.Agree(k, null!));
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithWrongPublicKey(KeyAgreementAlgorithm a)
        {
            using var k1 = new Key(a);
            using var k2 = new Key(SignatureAlgorithm.Ed25519);
            Assert.Same(a, k1.Algorithm);
            Assert.NotSame(a, k2.Algorithm);

            Assert.Throws<ArgumentException>("otherPartyPublicKey", () => a.Agree(k1, k2.PublicKey));
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeSuccess(KeyAgreementAlgorithm a)
        {
            using var k1 = new Key(a);
            using var k2 = new Key(a);

            using var s1 = a.Agree(k1, k2.PublicKey) ?? throw new Xunit.Sdk.NotNullException();
            Assert.NotNull(s1);
            Assert.Equal(a.SharedSecretSize, s1.Size);

            using var s2 = a.Agree(k2, k1.PublicKey) ?? throw new Xunit.Sdk.NotNullException();
            Assert.NotNull(s2);
            Assert.Equal(a.SharedSecretSize, s2.Size);
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeSelf(KeyAgreementAlgorithm a)
        {
            using var k = new Key(a);
            using var s = a.Agree(k, k.PublicKey) ?? throw new Xunit.Sdk.NotNullException();
            Assert.NotNull(s);
            Assert.Equal(a.SharedSecretSize, s.Size);
        }

        #endregion

        #region CreateKey

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void CreateKey(KeyAgreementAlgorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
            Assert.Same(a, k.Algorithm);
            Assert.True(k.HasPublicKey);
            Assert.NotNull(k.PublicKey);
            Assert.Same(a, k.PublicKey.Algorithm);
            Assert.Equal(a.PublicKeySize, k.PublicKey.Size);
            Assert.Equal(a.PrivateKeySize, k.Size);

            var actual = k.Export(KeyBlobFormat.RawPrivateKey);

            var unexpected = new byte[actual.Length];
            Utilities.Fill(unexpected, actual[0]);

            Assert.NotEqual(unexpected, actual);
        }

        #endregion
    }
}
