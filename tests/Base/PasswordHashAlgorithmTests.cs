using System;
using NSec.Cryptography;
using NSec.Experimental.PasswordBased;
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
            Assert.True(a.SaltSize > 0);
            Assert.True(a.MaxCount > 0);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithNullPassword(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("password", () => a.DeriveBytes(null!, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize - 1), 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize + 1), 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithNegativeCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize), -1));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSmallCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            var b = a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize), 3);

            Assert.NotNull(b);
            Assert.Equal(3, b.Length);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var b = a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize), 32);

            Assert.NotNull(b);
            Assert.Equal(32, b.Length);
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithNullPassword(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("password", () => a.DeriveBytes(null!, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize - 1), Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize + 1), Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSmallCount(PasswordBasedKeyDerivationAlgorithm a)
        {
            a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize), new byte[3]);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            a.DeriveBytes(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize), new byte[32]);
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithNullPassword(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("password", () => a.DeriveKey(null!, ReadOnlySpan<byte>.Empty, null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize - 1), null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize + 1), null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithNullAlgorithm(PasswordBasedKeyDerivationAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize), null!));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeySuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var x = AeadAlgorithm.ChaCha20Poly1305;

            using var k = a.DeriveKey(s_password, Utilities.RandomBytes.Slice(0, a.SaltSize), x);
            Assert.NotNull(k);
            Assert.Same(x, k.Algorithm);
        }

        #endregion
    }
}
