using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class KeyDerivationAlgorithm2Tests
    {
        public static readonly TheoryData<KeyDerivationAlgorithm2> KeyDerivationAlgorithms2 = Registry.KeyDerivationAlgorithms2;

        #region Extract #1

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractWithNullSecret(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.Extract((SharedSecret)null!, []));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractWithEmptySalt(KeyDerivationAlgorithm2 a)
        {
            var expected = a.Extract([], new byte[a.PseudorandomKeySize]);
            var actual = a.Extract([], []);

            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractSuccess(KeyDerivationAlgorithm2 a)
        {
            var actual = a.Extract([], []);

            Assert.NotNull(actual);
            Assert.Equal(a.PseudorandomKeySize, actual.Length);
        }

        #endregion

        #region Extract #2

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractWithSpanWithNullSecret(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentNullException>("sharedSecret", () => a.Extract((SharedSecret)null!, [], []));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractWithSpanTooShort(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.Extract([], [], new byte[a.PseudorandomKeySize - 1]));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractWithSpanTooLong(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.Extract([], [], new byte[a.PseudorandomKeySize + 1]));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractWithSpanWithEmptySalt(KeyDerivationAlgorithm2 a)
        {
            var expected = new byte[a.PseudorandomKeySize];
            var actual = new byte[expected.Length];

            a.Extract([], new byte[a.PseudorandomKeySize], expected);
            a.Extract([], [], actual);

            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractWithSpanWithSaltOverlapping(KeyDerivationAlgorithm2 a)
        {
            var expected = new byte[a.PseudorandomKeySize];
            var actual = Utilities.RandomBytes[..a.PseudorandomKeySize].ToArray();

            a.Extract([], actual, expected);
            a.Extract([], actual, actual);

            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExtractWithSpanSuccess(KeyDerivationAlgorithm2 a)
        {
            var actual = new byte[a.PseudorandomKeySize];

            a.Extract([], [], actual);
        }

        #endregion

        #region Expand #1

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandWithCountWithPrkTooShort(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.Expand(Utilities.RandomBytes[..(a.PseudorandomKeySize - 1)], [], 0));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandWithNegativeCount(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.Expand(Utilities.RandomBytes[..a.PseudorandomKeySize], [], -1));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandWithCountTooLarge(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.Expand(Utilities.RandomBytes[..a.PseudorandomKeySize], [], a.MaxCount + 1));
        }

        [Fact]
        public static void ExpandSuccess()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            var ikm = Utilities.RandomBytes[0..64];
            var salt = Utilities.RandomBytes[64..96];
            var info = Utilities.RandomBytes[96..128];

            var expected = a.DeriveBytes(ikm, salt, info, 256);
            var actual = a.Expand(a.Extract(ikm, salt), info, expected.Length);

            Assert.Equal(expected, actual);
        }

        #endregion

        #region Expand #2

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandWithSpanWithPrkTooShort(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.Expand(Utilities.RandomBytes[..(a.PseudorandomKeySize - 1)], [], []));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandWithSpanTooLarge(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentException>("bytes", () => a.Expand(Utilities.RandomBytes[..a.PseudorandomKeySize], [], new byte[a.MaxCount + 1]));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandWithKeyOverlapping(KeyDerivationAlgorithm2 a)
        {
            var b = new byte[200];

            Assert.Throws<ArgumentException>("bytes", () => a.Expand(b.AsSpan(10, a.PseudorandomKeySize), [], b.AsSpan(30, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.Expand(b.AsSpan(30, a.PseudorandomKeySize), [], b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandWithInfoOverlapping(KeyDerivationAlgorithm2 a)
        {
            var x = KeyAgreementAlgorithm.X25519;

            using var k = new Key(x);
            using var s = x.Agree(k, k.PublicKey)!;

            var b = new byte[200];

            var prk = a.Extract(s, []);

            Assert.Throws<ArgumentException>("bytes", () => a.Expand(prk, b.AsSpan(10, 100), b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("bytes", () => a.Expand(prk, b.AsSpan(60, 100), b.AsSpan(10, 100)));
        }

        [Fact]
        public static void ExpandWithSpanSuccess()
        {
            var a = KeyDerivationAlgorithm.HkdfSha256;

            var ikm = Utilities.RandomBytes[0..64];
            var salt = Utilities.RandomBytes[64..96];
            var info = Utilities.RandomBytes[96..128];

            var expected = a.DeriveBytes(ikm, salt, info, 256);
            var actual = new byte[expected.Length];

            a.Expand(a.Extract(ikm, salt), info, actual);

            Assert.Equal(expected, actual);
        }

        #endregion

        #region ExpandKey

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandKeyWithSpanWithPrkTooShort(KeyDerivationAlgorithm2 a)
        {
            var y = AeadAlgorithm.ChaCha20Poly1305;

            Assert.Throws<ArgumentException>("pseudorandomKey", () => a.ExpandKey(Utilities.RandomBytes[..(a.PseudorandomKeySize - 1)], [], y));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandKeyWithNullAlgorithm(KeyDerivationAlgorithm2 a)
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => a.ExpandKey(Utilities.RandomBytes[..a.PseudorandomKeySize], [], null!));
        }

        [Theory]
        [MemberData(nameof(KeyDerivationAlgorithms2))]
        public static void ExpandKeySuccess(KeyDerivationAlgorithm2 a)
        {
            var y = AeadAlgorithm.ChaCha20Poly1305;

            using var i = a.ExpandKey(Utilities.RandomBytes[..a.PseudorandomKeySize], [], y);
            Assert.NotNull(i);
            Assert.Same(y, i.Algorithm);
        }

        #endregion
    }
}
