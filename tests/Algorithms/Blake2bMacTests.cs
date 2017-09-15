using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Blake2bMacTests
    {
        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = new Blake2bMac();

            Assert.Equal(16, a.MinKeySize);
            Assert.Equal(32, a.DefaultKeySize);
            Assert.Equal(64, a.MaxKeySize);

            Assert.Equal(16, a.MinMacSize);
            Assert.Equal(32, a.DefaultMacSize);
            Assert.Equal(64, a.MaxMacSize);
        }

        #endregion

        #region Export #1

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public static void ExportImportRaw(int keySize)
        {
            var a = new Blake2bMac();
            var b = Utilities.RandomBytes.Slice(0, keySize);

            using (var k = Key.Import(a, b, KeyBlobFormat.RawSymmetricKey, KeyFlags.AllowArchiving))
            {
                Assert.Equal(KeyFlags.AllowArchiving, k.Flags);

                var expected = b.ToArray();
                var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

                Assert.Equal(expected, actual);
            }
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public static void ExportImportNSec(int keySize)
        {
            var a = new Blake2bMac();
            var b = Utilities.RandomBytes.Slice(0, keySize);

            using (var k1 = Key.Import(a, b, KeyBlobFormat.RawSymmetricKey, KeyFlags.AllowArchiving))
            {
                Assert.Equal(KeyFlags.AllowArchiving, k1.Flags);

                var n = k1.Export(KeyBlobFormat.NSecSymmetricKey);
                Assert.NotNull(n);

                using (var k2 = Key.Import(a, n, KeyBlobFormat.NSecSymmetricKey, KeyFlags.AllowArchiving))
                {
                    var expected = b.ToArray();
                    var actual = k2.Export(KeyBlobFormat.RawSymmetricKey);

                    Assert.Equal(expected, actual);
                }
            }
        }

        #endregion

        #region Sign #1

        [Fact]
        public static void HashWithNullKey()
        {
            var a = new Blake2bMac();

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void HashWithWrongKey()
        {
            var a = new Blake2bMac();

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty));
            }
        }

        public static void HashWithKeySuccess()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                var b = a.Sign(k, ReadOnlySpan<byte>.Empty);

                Assert.NotNull(b);
                Assert.Equal(a.DefaultMacSize, b.Length);
            }
        }

        #endregion

        #region Sign #2

        [Fact]
        public static void HashWithSizeWithNullKey()
        {
            var a = new Blake2bMac();

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty, 0));
        }

        [Fact]
        public static void HashWithSizeWithWrongKey()
        {
            var a = new Blake2bMac();

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty, 0));
            }
        }

        [Fact]
        public static void HashWithSizeTooSmall()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentOutOfRangeException>("macSize", () => a.Sign(k, ReadOnlySpan<byte>.Empty, a.MinMacSize - 1));
            }
        }

        [Fact]
        public static void HashWithSizeTooLarge()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentOutOfRangeException>("macSize", () => a.Sign(k, ReadOnlySpan<byte>.Empty, a.MaxMacSize + 1));
            }
        }

        [Fact]
        public static void HashWithMinSizeSuccess()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                var b = a.Sign(k, ReadOnlySpan<byte>.Empty, a.MinMacSize);

                Assert.NotNull(b);
                Assert.Equal(a.MinMacSize, b.Length);
            }
        }

        [Fact]
        public static void HashWithMaxSizeSuccess()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                var b = a.Sign(k, ReadOnlySpan<byte>.Empty, a.MaxMacSize);

                Assert.NotNull(b);
                Assert.Equal(a.MaxMacSize, b.Length);
            }
        }

        #endregion

        #region Sign #3

        [Fact]
        public static void HashWithSpanWithNullKey()
        {
            var a = new Blake2bMac();

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Fact]
        public static void HashWithSpanWithWrongKey()
        {
            var a = new Blake2bMac();

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Fact]
        public static void HashWithSpanTooSmall()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("mac", () => a.Sign(k, ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize - 1]));
            }
        }

        [Fact]
        public static void HashWithSpanTooLarge()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("mac", () => a.Sign(k, ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize + 1]));
            }
        }

        [Fact]
        public static void HashWithMinSpanSuccess()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                a.Sign(k, ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize]);
            }
        }

        [Fact]
        public static void HashWithMaxSpanSuccess()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a))
            {
                a.Sign(k, ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize]);
            }
        }

        #endregion

        #region CreateKey

        [Fact]
        public static void CreateKey()
        {
            var a = new Blake2bMac();

            using (var k = new Key(a, KeyFlags.AllowArchiving))
            {
                var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

                var unexpected = new byte[actual.Length];
                Utilities.Fill(unexpected, actual[0]);

                Assert.NotEqual(unexpected, actual);
            }
        }

        #endregion
    }
}
