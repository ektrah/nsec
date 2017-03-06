using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class SignatureAlgorithmTests
    {
        public static readonly TheoryData<Type> SignatureAlgorithms = Registry.SignatureAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.PublicKeySize > 0);
            Assert.True(a.PrivateKeySize > 0);
            Assert.True(a.SignatureSize > 0);
        }

        #endregion

        #region Sign #1

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void SignWithNullKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void SignWithWrongKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new X25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void SignSuccess(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var b = a.Sign(k, ReadOnlySpan<byte>.Empty);

                Assert.NotNull(b);
                Assert.Equal(a.SignatureSize, b.Length);
            }
        }

        #endregion

        #region Sign #2

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void SignWithSpanWithNullKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void SignWithSpanWithWrongKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new X25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void SignWithSpanWrongSize(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("signature", () => a.Sign(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void SignWithSpanSuccess(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                a.Sign(k, ReadOnlySpan<byte>.Empty, new byte[a.SignatureSize]);
            }
        }

        #endregion

        #region TryVerify

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void TryVerifyWithNullKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("publicKey", () => a.TryVerify(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void TryVerifyWithWrongKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new X25519()))
            {
                Assert.Throws<ArgumentException>("publicKey", () => a.TryVerify(k.PublicKey, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void TryVerifyWithWrongSize(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.False(a.TryVerify(k.PublicKey, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void TryVerifySuccess(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var s = a.Sign(k, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(s);
                Assert.Equal(a.SignatureSize, s.Length);

                Assert.True(a.TryVerify(k.PublicKey, ReadOnlySpan<byte>.Empty, s));
            }
        }

        #endregion

        #region Verify

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void VerifyWithNullKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("publicKey", () => a.Verify(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void VerifyWithWrongKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new X25519()))
            {
                Assert.Throws<ArgumentException>("publicKey", () => a.Verify(k.PublicKey, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void VerifyWithWrongSize(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<CryptographicException>(() => a.Verify(k.PublicKey, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void VerifySuccess(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var s = a.Sign(k, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(s);
                Assert.Equal(a.SignatureSize, s.Length);

                a.Verify(k.PublicKey, ReadOnlySpan<byte>.Empty, s);
            }
        }

        #endregion

        #region CreateKey

        [Theory]
        [MemberData(nameof(SignatureAlgorithms))]
        public static void CreateKey(Type algorithmType)
        {
            var a = (SignatureAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.AllowArchiving))
            {
                var actual = k.Export(KeyBlobFormat.RawPrivateKey);

                var unexpected = new byte[actual.Length];
                Utilities.Fill(unexpected, 0xDB);

                Assert.NotEqual(unexpected, actual);
            }
        }

        #endregion
    }
}
