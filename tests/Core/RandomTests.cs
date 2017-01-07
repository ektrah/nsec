using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Core
{
    public static class RandomTests
    {
        #region GenerateBytes #1

        [Fact]
        public static void GenerateBytesWithNegativeCount()
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => SecureRandom.GenerateBytes(-1));
        }

        [Fact]
        public static void GenerateBytesWithZeroCount()
        {
            var bytes = SecureRandom.GenerateBytes(0);

            Assert.NotNull(bytes);
            Assert.Equal(0, bytes.Length);
        }

        [Theory]
        [InlineData(15)]
        [InlineData(31)]
        [InlineData(63)]
        public static void GenerateBytesWithCount(int count)
        {
            var bytes = SecureRandom.GenerateBytes(count);

            Assert.NotNull(bytes);
            Assert.Equal(count, bytes.Length);
            Assert.NotEqual(new byte[count], bytes);
        }

        #endregion

        #region GenerateBytes #2

        [Fact]
        public static void GenerateBytesWithEmptySpan()
        {
            SecureRandom.GenerateBytes(new byte[0]);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(15)]
        [InlineData(63)]
        public static void GenerateBytesWithSpan(int count)
        {
            var bytes = new byte[count];

            SecureRandom.GenerateBytes(bytes);

            Assert.NotEqual(new byte[count], bytes);
        }

        #endregion
    }
}
