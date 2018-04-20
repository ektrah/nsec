using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class KeyAgreementAlgorithmTests
    {
        public static readonly TheoryData<Type> KeyAgreementAlgorithms = Registry.KeyAgreementAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.PublicKeySize > 0);
            Assert.True(a.PrivateKeySize > 0);
            Assert.True(a.SharedSecretSize > 0);
        }

        #endregion

        #region Agree

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithNullKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Agree(null, null));
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithDisposedKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k2 = new Key(a))
            {
                var k1 = new Key(a);
                k1.Dispose();
                Assert.Throws<ObjectDisposedException>(() => a.Agree(k1, k2.PublicKey));
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithWrongKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("key", () => a.Agree(k, null));
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithNullPublicKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Same(a, k.Algorithm);

                Assert.Throws<ArgumentNullException>("otherPartyPublicKey", () => a.Agree(k, null));
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeWithWrongPublicKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k1 = new Key(a))
            using (var k2 = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Same(a, k1.Algorithm);
                Assert.NotSame(a, k2.Algorithm);

                Assert.Throws<ArgumentException>("otherPartyPublicKey", () => a.Agree(k1, k2.PublicKey));
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeSuccess(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k1 = new Key(a))
            using (var k2 = new Key(a))
            using (var s1 = a.Agree(k1, k2.PublicKey))
            using (var s2 = a.Agree(k2, k1.PublicKey))
            {
                Assert.NotNull(s1);
                Assert.Equal(a.SharedSecretSize, s1.Size);

                Assert.NotNull(s2);
                Assert.Equal(a.SharedSecretSize, s2.Size);
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void AgreeSelf(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            using (var s = a.Agree(k, k.PublicKey))
            {
                Assert.NotNull(s);
                Assert.Equal(a.SharedSecretSize, s.Size);
            }
        }

        #endregion

        #region TryAgree

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void TryAgreeWithNullKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.TryAgree(null, null, out SharedSecret s));
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void TryAgreeWithDisposedKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k2 = new Key(a))
            {
                var k = new Key(a);
                k.Dispose();
                Assert.Throws<ObjectDisposedException>(() => a.TryAgree(k, k2.PublicKey, out SharedSecret s));
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void TryAgreeWithWrongKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("key", () => a.TryAgree(k, null, out SharedSecret s));
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void TryAgreeWithNullPublicKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentNullException>("otherPartyPublicKey", () => a.TryAgree(k, null, out SharedSecret s));
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void TryAgreeWithWrongPublicKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k1 = new Key(a))
            using (var k2 = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("otherPartyPublicKey", () => a.TryAgree(k1, k2.PublicKey, out SharedSecret s));
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void TryAgreeSuccess(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k1 = new Key(a))
            using (var k2 = new Key(a))
            {
                Assert.True(a.TryAgree(k1, k2.PublicKey, out SharedSecret s1));
                Assert.True(a.TryAgree(k2, k1.PublicKey, out SharedSecret s2));

                using (s1)
                using (s2)
                {
                    Assert.NotNull(s1);
                    Assert.Equal(a.SharedSecretSize, s1.Size);

                    Assert.NotNull(s2);
                    Assert.Equal(a.SharedSecretSize, s2.Size);
                }
            }
        }

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void TryAgreeSelf(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.True(a.TryAgree(k, k.PublicKey, out SharedSecret s));

                using (s)
                {
                    Assert.NotNull(s);
                    Assert.Equal(a.SharedSecretSize, s.Size);
                }
            }
        }

        #endregion

        #region CreateKey

        [Theory]
        [MemberData(nameof(KeyAgreementAlgorithms))]
        public static void CreateKey(Type algorithmType)
        {
            var a = (KeyAgreementAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving }))
            {
                Assert.Same(a, k.Algorithm);
                Assert.NotNull(k.PublicKey);
                Assert.Same(a, k.PublicKey.Algorithm);
                Assert.Equal(a.PublicKeySize, k.PublicKey.Size);
                Assert.Equal(a.PrivateKeySize, k.Size);

                var actual = k.Export(KeyBlobFormat.RawPrivateKey);

                var unexpected = new byte[actual.Length];
                Utilities.Fill(unexpected, actual[0]);

                Assert.NotEqual(unexpected, actual);
            }
        }

        #endregion
    }
}
