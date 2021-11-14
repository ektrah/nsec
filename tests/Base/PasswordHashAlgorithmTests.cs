using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class PasswordHashAlgorithmTests
    {
        public static readonly TheoryData<PasswordBasedKeyDerivationAlgorithm> PasswordHashAlgorithms = Registry.PasswordHashAlgorithms;

        private const string s_password = "passw0rd123";

        #region Properties

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void Properties(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.InRange(a.MaxCount, 0, int.MaxValue);
            Assert.InRange(a.MinSaltSize, 0, a.MaxSaltSize);
            Assert.InRange(a.MaxSaltSize, a.MinSaltSize, int.MaxValue);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..(a.MinSaltSize - 1)], 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..(a.MaxSaltSize + 1)], 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithNegativeCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..a.MinSaltSize], -1));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSmallCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            var b = a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..a.MinSaltSize], 3);

            Assert.NotNull(b);
            Assert.Equal(3, b.Length);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var b = a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..a.MinSaltSize], 32);

            Assert.NotNull(b);
            Assert.Equal(32, b.Length);
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..(a.MinSaltSize - 1)], Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..(a.MaxSaltSize + 1)], Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSmallCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..a.MinSaltSize], new byte[3]);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            a.DeriveBytes(Utilities.RandomBytes[..13], Utilities.RandomBytes[..a.MinSaltSize], new byte[32]);
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(Utilities.RandomBytes[..13], Utilities.RandomBytes[..(a.MinSaltSize - 1)], null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(Utilities.RandomBytes[..13], Utilities.RandomBytes[..(a.MaxSaltSize + 1)], null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithNullAlgorithm(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(Utilities.RandomBytes[..13], Utilities.RandomBytes[..a.MinSaltSize], null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeySuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var x = AeadAlgorithm.ChaCha20Poly1305;

            using var k = a.DeriveKey(Utilities.RandomBytes[..13], Utilities.RandomBytes[..a.MinSaltSize], x);
            Assert.NotNull(k);
            Assert.Same(x, k.Algorithm);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesNull(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("password", () => a.DeriveBytes((string)null!, Utilities.RandomBytes[..a.MinSaltSize], 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, Utilities.RandomBytes[..(a.MinSaltSize - 1)], 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithNegativeCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s_password, Utilities.RandomBytes[..a.MinSaltSize], -1));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithSmallCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            var b = a.DeriveBytes(s_password, Utilities.RandomBytes[..a.MinSaltSize], 3);

            Assert.NotNull(b);
            Assert.Equal(3, b.Length);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var b = a.DeriveBytes(s_password, Utilities.RandomBytes[..a.MinSaltSize], 32);

            Assert.NotNull(b);
            Assert.Equal(32, b.Length);
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithSpanNull(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("password", () => a.DeriveBytes((string)null!, Utilities.RandomBytes[..a.MinSaltSize], Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithSpanWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, Utilities.RandomBytes[..(a.MinSaltSize - 1)], Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithSpanWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithSpanWithSmallCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            a.DeriveBytes(s_password, Utilities.RandomBytes[..a.MinSaltSize], new byte[3]);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveBytesWithSpanSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            a.DeriveBytes(s_password, Utilities.RandomBytes[..a.MinSaltSize], new byte[32]);
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveKeyNull(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("password", () => a.DeriveKey((string)null!, Utilities.RandomBytes[..a.MinSaltSize], null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveKeyWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s_password, Utilities.RandomBytes[..(a.MinSaltSize - 1)], null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveKeyWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s_password, Utilities.RandomBytes[..(a.MaxSaltSize + 1)], null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveKeyWithNullAlgorithm(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(s_password, Utilities.RandomBytes[..a.MinSaltSize], null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringDeriveKeySuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var x = AeadAlgorithm.ChaCha20Poly1305;

            using var k = a.DeriveKey(s_password, Utilities.RandomBytes[..a.MinSaltSize], x);
            Assert.NotNull(k);
            Assert.Same(x, k.Algorithm);
        }

        #endregion
    }
}
