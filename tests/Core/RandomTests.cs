using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Core
{
    public static class RandomTests
    {
        public static readonly TheoryData<Algorithm> AsymmetricKeyAlgorithms = Registry.AsymmetricAlgorithms;
        public static readonly TheoryData<Algorithm> SymmetricKeyAlgorithms = Registry.SymmetricAlgorithms;
        public static readonly TheoryData<Algorithm> KeylessAlgorithms = Registry.KeylessAlgorithms;

        #region GenerateBytes #1

        [Fact]
        public static void GenerateBytesWithNegativeCount()
        {
            Assert.Throws<ArgumentOutOfRangeException>("count", () => RandomGenerator.Default.GenerateBytes(-1));
        }

        [Fact]
        public static void GenerateBytesWithZeroCount()
        {
            var bytes = RandomGenerator.Default.GenerateBytes(0);

            Assert.NotNull(bytes);
            Assert.Empty(bytes);
        }

        [Theory]
        [InlineData(15)]
        [InlineData(31)]
        [InlineData(63)]
        public static void GenerateBytesWithCount(int count)
        {
            var bytes = RandomGenerator.Default.GenerateBytes(count);

            Assert.NotNull(bytes);
            Assert.Equal(count, bytes.Length);
            Assert.NotEqual(new byte[count], bytes);
        }

        #endregion

        #region GenerateBytes #2

        [Fact]
        public static void GenerateBytesWithEmptySpan()
        {
            RandomGenerator.Default.GenerateBytes(Span<byte>.Empty);
        }

        [Theory]
        [InlineData(15)]
        [InlineData(31)]
        [InlineData(63)]
        public static void GenerateBytesWithSpan(int count)
        {
            var bytes = new byte[count];

            RandomGenerator.Default.GenerateBytes(bytes);

            Assert.NotEqual(new byte[count], bytes);
        }

        [Fact]
        public static void GenerateBytesWithSpanOffset()
        {
            var bytes = Utilities.RandomBytes.Slice(0, 400).ToArray();

            RandomGenerator.Default.GenerateBytes(bytes.AsSpan(100, 200));

            Assert.Equal(Utilities.RandomBytes.Slice(0, 100).ToArray(), bytes.AsSpan(0, 100).ToArray());
            Assert.NotEqual(Utilities.RandomBytes.Slice(100, 200).ToArray(), bytes.AsSpan(100, 200).ToArray());
            Assert.Equal(Utilities.RandomBytes.Slice(300, 100).ToArray(), bytes.AsSpan(300, 100).ToArray());
        }

        [Fact]
        public static void GenerateBytesWithSpanEmpty()
        {
            var bytes = Utilities.RandomBytes.Slice(0, 400).ToArray();

            RandomGenerator.Default.GenerateBytes(bytes.AsSpan(100, 0));

            Assert.Equal(Utilities.RandomBytes.Slice(0, 400).ToArray(), bytes.AsSpan(0, 400).ToArray());
        }

        #endregion

        #region GenerateInt32 #1

        [Fact]
        public static void GenerateInt32()
        {
            for (var i = 0; i < 10000; i++)
            {
                var actual = RandomGenerator.Default.GenerateInt32();
                Assert.InRange(actual, 0, int.MaxValue);
            }
        }

        #endregion

        #region GenerateInt32 #2

        [Fact]
        public static void GenerateInt32WithPositiveUpperBound()
        {
            const int upperExclusive = 198400021;

            for (var i = 0; i < 10000; i++)
            {
                var actual = RandomGenerator.Default.GenerateInt32(upperExclusive);
                Assert.InRange(actual, 0, upperExclusive - 1);
            }
        }

        [Fact]
        public static void GenerateInt32WithNegativeUpperBound()
        {
            const int upperExclusive = -198400021;

            Assert.Throws<ArgumentOutOfRangeException>("maxValue", () => RandomGenerator.Default.GenerateInt32(upperExclusive));
        }

        [Fact]
        public static void GenerateInt32WithUpperBoundZero()
        {
            const int upperExclusive = 0;

            var actual = RandomGenerator.Default.GenerateInt32(upperExclusive);
            Assert.Equal(0, actual);
        }

        [Fact]
        public static void GenerateInt32WithUpperBoundOne()
        {
            const int upperExclusive = 1;

            var actual = RandomGenerator.Default.GenerateInt32(upperExclusive);
            Assert.Equal(0, actual);
        }

        #endregion

        #region GenerateInt32 #3

        [Fact]
        public static void GenerateInt32WithPositiveLowerBound()
        {
            const int lowerInclusive = 198400021;
            const int upperExclusive = 2147480009;

            for (var i = 0; i < 10000; i++)
            {
                var actual = RandomGenerator.Default.GenerateInt32(lowerInclusive, upperExclusive);
                Assert.InRange(actual, lowerInclusive, upperExclusive - 1);
            }
        }

        [Fact]
        public static void GenerateInt32WithNegativeLowerBound()
        {
            const int lowerInclusive = -198400021;
            const int upperExclusive = 2147480009;

            for (var i = 0; i < 10000; i++)
            {
                var actual = RandomGenerator.Default.GenerateInt32(lowerInclusive, upperExclusive);
                Assert.InRange(actual, lowerInclusive, upperExclusive - 1);
            }
        }

        [Fact]
        public static void GenerateInt32WithInvalidLowerBound()
        {
            const int lowerInclusive = 2147480009;
            const int upperExclusive = 198400021;

            Assert.Throws<ArgumentException>("minValue", () => RandomGenerator.Default.GenerateInt32(lowerInclusive, upperExclusive));
        }

        [Fact]
        public static void GenerateInt32WithSameLowerBoundZero()
        {
            const int lowerInclusive = 198400021;
            const int upperExclusive = 198400021 + 0;

            var actual = RandomGenerator.Default.GenerateInt32(lowerInclusive, upperExclusive);
            Assert.Equal(lowerInclusive, actual);
        }

        [Fact]
        public static void GenerateInt32WithSameLowerBoundOne()
        {
            const int lowerInclusive = 198400021;
            const int upperExclusive = 198400021 + 1;

            var actual = RandomGenerator.Default.GenerateInt32(lowerInclusive, upperExclusive);
            Assert.Equal(lowerInclusive, actual);
        }

        #endregion

        #region GenerateKey

        [Fact]
        public static void GenerateKeyWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => RandomGenerator.Default.GenerateKey(null!));
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void GenerateKeyWithAlgorithm(Algorithm a)
        {
            using var key = RandomGenerator.Default.GenerateKey(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.NotNull(key);
            Assert.Same(a, key.Algorithm);
            Assert.Equal(KeyExportPolicies.None, key.ExportPolicy);
        }

        [Theory]
        [MemberData(nameof(KeylessAlgorithms))]
        public static void GenerateKeyWithAlgorithmThatDoesNotUseKeys(Algorithm a)
        {
            Assert.Throws<NotSupportedException>(() => RandomGenerator.Default.GenerateKey(a));
        }

        #endregion

        #region GenerateUInt32 #1

        [Fact]
        public static void GenerateUInt32()
        {
            for (var i = 0; i < 10000; i++)
            {
                var actual = RandomGenerator.Default.GenerateUInt32();
                Assert.InRange(actual, uint.MinValue, uint.MaxValue);
            }
        }

        #endregion

        #region GenerateUInt32 #2

        [Fact]
        public static void GenerateUInt32WithPositiveUpperBound()
        {
            const uint upperExclusive = 198400021;

            for (var i = 0; i < 10000; i++)
            {
                var actual = RandomGenerator.Default.GenerateUInt32(upperExclusive);
                Assert.InRange(actual, uint.MinValue, upperExclusive - 1);
            }
        }

        [Fact]
        public static void GenerateUInt32WithUpperBoundZero()
        {
            const uint upperExclusive = 0;

            var actual = RandomGenerator.Default.GenerateUInt32(upperExclusive);
            Assert.Equal(uint.MinValue, actual);
        }

        [Fact]
        public static void GenerateUInt32WithUpperBoundOne()
        {
            const uint upperExclusive = 1;

            var actual = RandomGenerator.Default.GenerateUInt32(upperExclusive);
            Assert.Equal(uint.MinValue, actual);
        }

        #endregion

        #region GenerateUInt32 #3

        [Fact]
        public static void GenerateUInt32WithPositiveLowerBound()
        {
            const uint lowerInclusive = 198400021;
            const uint upperExclusive = 2147480009;

            for (var i = 0; i < 10000; i++)
            {
                var actual = RandomGenerator.Default.GenerateUInt32(lowerInclusive, upperExclusive);
                Assert.InRange(actual, lowerInclusive, upperExclusive - 1);
            }
        }

        [Fact]
        public static void GenerateUInt32WithInvalidLowerBound()
        {
            const uint lowerInclusive = 2147480009;
            const uint upperExclusive = 198400021;

            Assert.Throws<ArgumentException>("minValue", () => RandomGenerator.Default.GenerateUInt32(lowerInclusive, upperExclusive));
        }

        [Fact]
        public static void GenerateUInt32WithSameLowerBoundZero()
        {
            const uint lowerInclusive = 198400021;
            const uint upperExclusive = 198400021 + 0;

            var actual = RandomGenerator.Default.GenerateUInt32(lowerInclusive, upperExclusive);
            Assert.Equal(lowerInclusive, actual);
        }

        [Fact]
        public static void GenerateUInt32WithSameLowerBoundOne()
        {
            const uint lowerInclusive = 198400021;
            const uint upperExclusive = 198400021 + 1;

            var actual = RandomGenerator.Default.GenerateUInt32(lowerInclusive, upperExclusive);
            Assert.Equal(lowerInclusive, actual);
        }

        #endregion
    }
}
