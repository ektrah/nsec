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
            Assert.Throws<ArgumentException>("inputKeyingMaterial", () => a.DeriveBytes([], [], [], 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..100], Utilities.RandomBytes[..(a.MinSaltSize - 1)], [], 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..100], Utilities.RandomBytes[..(a.MaxSaltSize + 1)], [], 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithNegativeCount(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(Utilities.RandomBytes[..100], [], [], -1));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithCountTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxCount == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(Utilities.RandomBytes[..100], [], [], a.MaxCount + 1));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithZeroCount(KeyDerivationAlgorithm a)
        {
            var b = a.DeriveBytes(Utilities.RandomBytes[..100], [], [], 0);

            Assert.NotNull(b);
            Assert.Empty(b);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithMaxCount(KeyDerivationAlgorithm a)
        {
            var count = Math.Min(a.MaxCount, 500173);

            var b = a.DeriveBytes(Utilities.RandomBytes[..100], [], [], count);

            Assert.NotNull(b);
            Assert.Equal(count, b.Length);
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithEmptySecretAndSpan(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("inputKeyingMaterial", () => a.DeriveBytes([], [], [], []));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSpanWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..100], Utilities.RandomBytes[..(a.MinSaltSize - 1)], [], []));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSpanWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..100], Utilities.RandomBytes[..(a.MaxSaltSize + 1)], [], []));
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

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], b.AsSpan(10, 100), [], b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], b.AsSpan(60, 100), [], b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithInfoOverlapping(KeyDerivationAlgorithm a)
        {
            var b = new byte[200];

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], [], b.AsSpan(10, 100), b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], [], b.AsSpan(60, 100), b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithSpanTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxCount == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(Utilities.RandomBytes[..100], [], [], new byte[a.MaxCount + 1]));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithEmptySpan(KeyDerivationAlgorithm a)
        {
            a.DeriveBytes(Utilities.RandomBytes[..100], [], [], []);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesSpanWithMaxSpan(KeyDerivationAlgorithm a)
        {
            var count = Math.Min(a.MaxCount, 500173);

            a.DeriveBytes(Utilities.RandomBytes[..100], [], [], new byte[count]);
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanWithEmptySecret(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("inputKeyingMaterial", () => a.DeriveKey([], [], [], null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanWithSaltTooSmall(KeyDerivationAlgorithm a)
        {
            if (a.MinSaltSize == 0)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(Utilities.RandomBytes[..100], Utilities.RandomBytes[0..(a.MinSaltSize - 1)], [], null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanWithSaltTooLarge(KeyDerivationAlgorithm a)
        {
            if (a.MaxSaltSize == int.MaxValue)
            {
                return;
            }

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(Utilities.RandomBytes[..100], Utilities.RandomBytes[0..(a.MaxSaltSize + 1)], [], null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanWithNullAlgorithm(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(Utilities.RandomBytes[..100], [], [], null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySpanSuccess(KeyDerivationAlgorithm a)
        {
            var y = AeadAlgorithm.ChaCha20Poly1305;

            using var i = a.DeriveKey(Utilities.RandomBytes[..100], [], [], y);
            Assert.NotNull(i);
            Assert.Same(y, i.Algorithm);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNullSecret(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveBytes((SharedSecret)null!, [], [], 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithDisposedSecret(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes[..32], SharedSecretBlobFormat.RawSharedSecret);
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveBytes(s, [], [], 200));
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

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, Utilities.RandomBytes[..(a.MinSaltSize - 1)], [], 0));
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

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], [], 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNegativeCount(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s, [], [], -1));
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

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s, [], [], a.MaxCount + 1));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithZeroCount(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            var b = a.DeriveBytes(s, [], [], 0);

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

            var b = a.DeriveBytes(s, [], [], count);

            Assert.NotNull(b);
            Assert.Equal(count, b.Length);
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithNullSecretAndSpan(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveBytes((SharedSecret)null!, [], [], []));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithDisposedSecretAndSpan(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes[..32], SharedSecretBlobFormat.RawSharedSecret);
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveBytes(s, [], [], new byte[200]));
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

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, Utilities.RandomBytes[..(a.MinSaltSize - 1)], [], []));
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

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], [], []));
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

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, b.AsSpan(10, 100), [], b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, b.AsSpan(60, 100), [], b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithInfoOverlapping(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;
            var b = new byte[200];

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, [], b.AsSpan(10, 100), b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, [], b.AsSpan(60, 100), b.AsSpan(10, 100)));
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

            Assert.Throws<ArgumentException>("bytes", () => a.DeriveBytes(s, [], [], new byte[a.MaxCount + 1]));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithEmptySpan(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            a.DeriveBytes(s, [], [], []);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveBytesWithMaxSpan(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;
            var count = Math.Min(a.MaxCount, 500173);

            a.DeriveBytes(s, [], [], new byte[count]);
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithNullSecret(KeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.DeriveKey((SharedSecret)null!, [], [], null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithDisposedSecret(KeyDerivationAlgorithm a)
        {
            var s = SharedSecret.Import(Utilities.RandomBytes[..32], SharedSecretBlobFormat.RawSharedSecret);
            s.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.DeriveKey(s, [], [], AeadAlgorithm.ChaCha20Poly1305));
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

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s, Utilities.RandomBytes[..(a.MinSaltSize - 1)], [], null!));
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

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], [], null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeyWithNullAlgorithm(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(s, [], [], null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms))]
        public static void DeriveKeySuccess(KeyDerivationAlgorithm a)
        {
            var x = KeyAgreementAlgorithm.X25519;
            var y = AeadAlgorithm.ChaCha20Poly1305;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;
            using var i = a.DeriveKey(s, [], [], y);
            Assert.NotNull(i);
            Assert.Same(y, i.Algorithm);
        }

        #endregion
    }
}
