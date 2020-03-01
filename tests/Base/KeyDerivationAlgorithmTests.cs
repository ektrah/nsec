using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class KeyDerivationAlgorithmTests
    {
        public static readonly TheoryData<KeyDerivationAlgorithm> KeyDerivationAlgorithms = Registry.KeyDerivationAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void Properties(KeyDerivationAlgorithm a)
        {
            Assert.True(a.SupportsSalt || !a.SupportsSalt);
            Assert.True(a.MaxCount > 0);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNullSecret(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveBytes(null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithDisposedSecret(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes.Slice(0, 32));
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithUnusedSalt(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            if (a.SupportsSalt)
            {
                return;
            }

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, new byte[1], ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNegativeCount(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, -1));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithCountTooLarge(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            if (a.MaxCount == int.MaxValue)
            {
                return;
            }

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, a.MaxCount + 1));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithZeroCount(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            var b = a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0);

            Assert.NotNull(b);
            Assert.Empty(b);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithMaxCount(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;
            var count = Math.Min(a.MaxCount, 500173);

            var b = a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, count);

            Assert.NotNull(b);
            Assert.Equal(count, b.Length);
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNullSecretAndSpan(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveBytes(null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithDisposedSecretAndSpan(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes.Slice(0, 32));
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithSpanWithUnusedSalt(KeyDerivationAlgorithm a)
        {
            if (a.SupportsSalt)
            {
                return;
            }

            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, new byte[1], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithSaltOverlapping(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            if (!a.SupportsSalt)
            {
                return;
            }

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;
            var b = new byte[200];

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, b.AsSpan(10, 100), ReadOnlySpan<byte>.Empty, b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, b.AsSpan(60, 100), ReadOnlySpan<byte>.Empty, b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithInfoOverlapping(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;
            var b = new byte[200];

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, b.AsSpan(10, 100), b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, b.AsSpan(60, 100), b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithSpanTooLarge(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            if (a.MaxCount == int.MaxValue)
            {
                return;
            }

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[a.MaxCount + 1]));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithEmptySpan(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithMaxSpan(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;
            var count = Math.Min(a.MaxCount, 500173);

            a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[count]);
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithNullSecret(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveKey(null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithDisposedSecret(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes.Slice(0, 32));
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveKey(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, AeadAlgorithm.ChaCha20Poly1305));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithUnusedSalt(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            if (a.SupportsSalt)
            {
                return;
            }

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s, new byte[1], ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithNullAlgorithm(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySuccess(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;
            var y = AeadAlgorithm.ChaCha20Poly1305;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;
            using var i = a.DeriveKey(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, y);
            Assert.NotNull(k);
            Assert.Same(y, i.Algorithm);
        }

        #endregion
    }
}
