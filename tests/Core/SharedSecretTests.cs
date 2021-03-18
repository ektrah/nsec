using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Core
{
    public static class SharedSecretTests
    {
        #region Import

        [Fact]
        public static void ImportEmpty()
        {
            using var s = SharedSecret.Import(ReadOnlySpan<byte>.Empty);
            Assert.NotNull(s);
            Assert.Equal(0, s.Size);
        }

        [Fact]
        public static void ImportNonEmpty()
        {
            var b = Utilities.RandomBytes.Slice(0, 57);

            using var s = SharedSecret.Import(b);
            Assert.NotNull(s);
            Assert.Equal(b.Length, s.Size);
        }

        [Fact]
        public static void ImportZeros()
        {
            var b = new byte[64];

            using var s = SharedSecret.Import(b);
            Assert.NotNull(s);
            Assert.Equal(b.Length, s.Size);
        }

        [Fact]
        public static void ImportTooLong()
        {
            var b = new byte[129];

            Assert.Throws<ArgumentException>("sharedSecret", () => SharedSecret.Import(b));
        }

        #endregion

        #region Dispose

        [Fact]
        public static void DisposeMoreThanOnce()
        {
            var b = new byte[64];
            var s = SharedSecret.Import(b);
            Assert.NotNull(s);
            s.Dispose();
            s.Dispose();
            s.Dispose();
        }

        [Fact]
        public static void PropertiesAfterDispose()
        {
            var b = new byte[64];
            var s = SharedSecret.Import(b);
            s.Dispose();
            Assert.NotNull(s);
            Assert.Equal(b.Length, s.Size);
        }

        #endregion
    }
}
