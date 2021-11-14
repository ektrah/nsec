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
            Assert.InRange(a.MaxCount, 0, int.MaxValue);
            Assert.InRange(a.MinSaltSize, 0, a.MaxSaltSize);
            Assert.InRange(a.MaxSaltSize, a.MinSaltSize, int.MaxValue);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithEmptySecret(KeyDerivationAlgorithm a)
        {
            var count = 1000;

            var b = a.DeriveBytes(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, count);

            Assert.NotNull(b);
            Assert.Equal(count, b.Length);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..100], Utilities.RandomBytes[..(a.MinSaltSize - 1)], ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..100], Utilities.RandomBytes[..(a.MaxSaltSize + 1)], ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithNegativeCount(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, -1));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithCountTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxCount == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, a.MaxCount + 1));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithZeroCount(KeyDerivationAlgorithm a)
        {
            var b = a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0);

            Assert.NotNull(b);
            Assert.Empty(b);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithMaxCount(KeyDerivationAlgorithm a)
        {
            var count = Math.Min(a.MaxCount, 500173);

            var b = a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, count);

            Assert.NotNull(b);
            Assert.Equal(count, b.Length);
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithEmptySecretAndSpan(KeyDerivationAlgorithm a)
        {
            var count = 1000;

            a.DeriveBytes(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[count]);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSpanWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..100], Utilities.RandomBytes[..(a.MinSaltSize - 1)], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSpanWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..100], Utilities.RandomBytes[..(a.MaxSaltSize + 1)], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSaltOverlapping(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == 0)
            {
                return;
            }

            var b = new byte[200];

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], b.AsSpan(10, 100), ReadOnlySpan<byte>.Empty, b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], b.AsSpan(60, 100), ReadOnlySpan<byte>.Empty, b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithInfoOverlapping(KeyDerivationAlgorithm a)
        {
            var b = new byte[200];

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, b.AsSpan(10, 100), b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, b.AsSpan(60, 100), b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSpanTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxCount == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[a.MaxCount + 1]));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithEmptySpan(KeyDerivationAlgorithm a)
        {
            a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithMaxSpan(KeyDerivationAlgorithm a)
        {
            var count = Math.Min(a.MaxCount, 500173);

            a.DeriveBytes(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[count]);
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanWithEmptySecret(KeyDerivationAlgorithm a)
        {
            var y = AeadAlgorithm.ChaCha20Poly1305;

            using var i = a.DeriveKey(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, y);
            Assert.NotNull(i);
            Assert.Same(y, i.Algorithm);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(Utilities.RandomBytes[..100], Utilities.RandomBytes[0..(a.MinSaltSize - 1)], ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(Utilities.RandomBytes[..100], Utilities.RandomBytes[0..(a.MaxSaltSize + 1)], ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanWithNullAlgorithm(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanSuccess(KeyDerivationAlgorithm a)
        {
            var y = AeadAlgorithm.ChaCha20Poly1305;

            using var i = a.DeriveKey(Utilities.RandomBytes[..100], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, y);
            Assert.NotNull(i);
            Assert.Same(y, i.Algorithm);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNullSecret(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveBytes((SharedSecret)null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithDisposedSecret(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes[..32]);
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 200));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, Utilities.RandomBytes[..(a.MinSaltSize - 1)], ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], ReadOnlySpan<byte>.Empty, 0));
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
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveBytes((SharedSecret)null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithDisposedSecretAndSpan(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes[..32]);
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveBytes(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[200]));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithSpanWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, Utilities.RandomBytes[..(a.MinSaltSize - 1)], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithSpanWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithSaltOverlapping(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == 0)
            {
                return;
            }

            var x = KeyAgreementAlgorithm.X25519;

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
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveKey((SharedSecret)null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithDisposedSecret(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes[..32]);
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveKey(s, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, AeadAlgorithm.ChaCha20Poly1305));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s, Utilities.RandomBytes[..(a.MinSaltSize - 1)], ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], ReadOnlySpan<byte>.Empty, null!));
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
            Assert.NotNull(i);
            Assert.Same(y, i.Algorithm);
        }

        #endregion
    }
}
