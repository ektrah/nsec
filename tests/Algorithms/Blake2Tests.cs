using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Blake2Tests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = new Blake2();

            Assert.True(a.MinKeySize >= 0);
            Assert.True(a.DefaultKeySize >= a.MinKeySize);
            Assert.True(a.MaxKeySize >= a.DefaultKeySize);
            Assert.True(a.MaxKeySize <= 64);

            Assert.True(a.MinHashSize >= 1);
            Assert.True(a.DefaultHashSize >= a.MinHashSize);
            Assert.True(a.MaxHashSize >= a.DefaultHashSize);
            Assert.True(a.MaxHashSize <= 64);
        }

        #endregion

        #region Hash #1

        [Fact]
        public static void HashWithNullKey()
        {
            var a = new Blake2();

            Assert.Throws<ArgumentNullException>("key", () => a.Hash(null, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void HashWithWrongKey()
        {
            var a = new Blake2();

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Hash(k, ReadOnlySpan<byte>.Empty));
            }
        }

        public static void HashWithKeySuccess()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                var b = a.Hash(k, ReadOnlySpan<byte>.Empty);

                Assert.NotNull(b);
                Assert.Equal(a.DefaultHashSize, b.Length);
            }
        }

        #endregion

        #region Hash #2

        [Fact]
        public static void HashWithSizeWithNullKey()
        {
            var a = new Blake2();

            Assert.Throws<ArgumentNullException>("key", () => a.Hash(null, ReadOnlySpan<byte>.Empty, 0));
        }

        [Fact]
        public static void HashWithSizeWithWrongKey()
        {
            var a = new Blake2();

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Hash(k, ReadOnlySpan<byte>.Empty, 0));
            }
        }

        [Fact]
        public static void HashWithSizeTooSmall()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentOutOfRangeException>("hashSize", () => a.Hash(k, ReadOnlySpan<byte>.Empty, a.MinHashSize - 1));
            }
        }

        [Fact]
        public static void HashWithSizeTooLarge()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentOutOfRangeException>("hashSize", () => a.Hash(k, ReadOnlySpan<byte>.Empty, a.MaxHashSize + 1));
            }
        }

        [Fact]
        public static void HashWithMinSizeSuccess()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                var b = a.Hash(k, ReadOnlySpan<byte>.Empty, a.MinHashSize);

                Assert.NotNull(b);
                Assert.Equal(a.MinHashSize, b.Length);
            }
        }

        [Fact]
        public static void HashWithMaxSizeSuccess()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                var b = a.Hash(k, ReadOnlySpan<byte>.Empty, a.MaxHashSize);

                Assert.NotNull(b);
                Assert.Equal(a.MaxHashSize, b.Length);
            }
        }

        #endregion

        #region Hash #3

        [Fact]
        public static void HashWithSpanWithNullKey()
        {
            var a = new Blake2();

            Assert.Throws<ArgumentNullException>("key", () => a.Hash(null, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Fact]
        public static void HashWithSpanWithWrongKey()
        {
            var a = new Blake2();

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Hash(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Fact]
        public static void HashWithSpanTooSmall()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("hash", () => a.Hash(k, ReadOnlySpan<byte>.Empty, new byte[a.MinHashSize - 1]));
            }
        }

        [Fact]
        public static void HashWithSpanTooLarge()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("hash", () => a.Hash(k, ReadOnlySpan<byte>.Empty, new byte[a.MaxHashSize + 1]));
            }
        }

        [Fact]
        public static void HashWithMinSpanSuccess()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                a.Hash(k, ReadOnlySpan<byte>.Empty, new byte[a.MinHashSize]);
            }
        }

        [Fact]
        public static void HashWithMaxSpanSuccess()
        {
            var a = new Blake2();

            using (var k = new Key(a))
            {
                a.Hash(k, ReadOnlySpan<byte>.Empty, new byte[a.MaxHashSize]);
            }
        }

        #endregion
    }
}
