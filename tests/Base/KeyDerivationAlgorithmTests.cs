using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class KeyDerivationAlgorithmTests
    {
        public static readonly TheoryData<Type> KeyDerivationAlgorithms = Registry.KeyDerivationAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.UsesSalt || !a.UsesSalt);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNullSecret(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveBytes(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithUnusedSalt(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);

            if (!a.UsesSalt)
            {
                var x = new X25519();

                using (var k = new Key(x))
                using (var s = x.Agree(k, k.PublicKey))
                {
                    Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, new byte[1], ReadOnlySpan<byte>.Empty, 0));
                }
            }
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNegativeCount(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);
            var x = new X25519();

            using (var k = new Key(x))
            using (var s = x.Agree(k, k.PublicKey))
            {
                Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, -1));
            }
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithZeroCount(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);
            var x = new X25519();

            using (var k = new Key(x))
            using (var s = x.Agree(k, k.PublicKey))
            {
                var b = a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0);

                Assert.NotNull(b);
                Assert.Equal(0, b.Length);
            }
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNullSecretAndSpan(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveBytes(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithUnusedSaltAndSpan(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);

            if (!a.UsesSalt)
            {
                var x = new X25519();

                using (var k = new Key(x))
                using (var s = x.Agree(k, k.PublicKey))
                {
                    Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, new byte[1], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
                }
            }
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithEmptySpan(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);
            var x = new X25519();

            using (var k = new Key(x))
            using (var s = x.Agree(k, k.PublicKey))
            {
                a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty);
            }
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithNullSecret(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveKey(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, null));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithUnusedSalt(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);

            if (!a.UsesSalt)
            {
                var x = new X25519();

                using (var k = new Key(x))
                using (var s = x.Agree(k, k.PublicKey))
                {
                    Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s, new byte[1], ReadOnlySpan<byte>.Empty, null));
                }
            }
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithNullAlgorithm(Type algorithmType)
        {
            var a = (KeyDerivationAlgorithm)Activator.CreateInstance(algorithmType);
            var x = new X25519();

            using (var k = new Key(x))
            using (var s = x.Agree(k, k.PublicKey))
            {
                Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, null));
            }
        }

        #endregion
    }
}
