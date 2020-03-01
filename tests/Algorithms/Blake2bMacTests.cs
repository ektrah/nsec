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

            Assert.Equal(16, Blake2bMac.MinKeySize);
            Assert.Equal(64, Blake2bMac.MaxKeySize);
            Assert.Equal(16, Blake2bMac.MinMacSize);
            Assert.Equal(64, Blake2bMac.MaxMacSize);

            Assert.Equal(32, a.KeySize);
            Assert.Equal(32, a.MacSize);

            Assert.Equal(32, MacAlgorithm.Blake2b_128.KeySize);
            Assert.Equal(16, MacAlgorithm.Blake2b_128.MacSize);

            Assert.Equal(32, MacAlgorithm.Blake2b_256.KeySize);
            Assert.Equal(32, MacAlgorithm.Blake2b_256.MacSize);

            Assert.Equal(32, MacAlgorithm.Blake2b_512.KeySize);
            Assert.Equal(64, MacAlgorithm.Blake2b_512.MacSize);
        }

        [Theory]
        [InlineData(128 / 8, 128 / 8)]
        [InlineData(160 / 8, 160 / 8)]
        [InlineData(192 / 8, 192 / 8)]
        [InlineData(224 / 8, 224 / 8)]
        [InlineData(256 / 8, 256 / 8)]
        [InlineData(384 / 8, 384 / 8)]
        [InlineData(512 / 8, 512 / 8)]
        public static void PropertiesConstructed(int keySize, int macSize)
        {
            var a = new Blake2bMac(keySize, macSize);

            Assert.Equal(keySize, a.KeySize);
            Assert.Equal(macSize, a.MacSize);
        }

        #endregion

        #region Ctor #2

        [Fact]
        public static void CtorWithKeySizeTooSmall()
        {
            Assert.Throws<ArgumentOutOfRangeException>("keySize", () => new Blake2bMac(16 - 1, 16));
        }

        [Fact]
        public static void CtorWithKeySizeTooLarge()
        {
            Assert.Throws<ArgumentOutOfRangeException>("keySize", () => new Blake2bMac(64 + 1, 64));
        }

        [Fact]
        public static void CtorWithMacSizeTooSmall()
        {
            Assert.Throws<ArgumentOutOfRangeException>("macSize", () => new Blake2bMac(16, 16 - 1));
        }

        [Fact]
        public static void CtorWithMacSizeTooLarge()
        {
            Assert.Throws<ArgumentOutOfRangeException>("macSize", () => new Blake2bMac(64, 64 + 1));
        }

        #endregion

        #region Export #1

        [Theory]
        [InlineData(16, 16)]
        [InlineData(32, 32)]
        [InlineData(64, 64)]
        public static void ExportImportRaw(int keySize, int macSize)
        {
            var a = new Blake2bMac(keySize, macSize);
            var b = Utilities.RandomBytes.Slice(0, keySize);

            Assert.Equal(keySize, a.KeySize);
            Assert.Equal(macSize, a.MacSize);

            using var k = Key.Import(a, b, KeyBlobFormat.RawSymmetricKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
            Assert.Equal(KeyExportPolicies.AllowPlaintextArchiving, k.ExportPolicy);

            var expected = b.ToArray();
            var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(16, 16)]
        [InlineData(32, 32)]
        [InlineData(64, 64)]
        public static void ExportImportNSec(int keySize, int macSize)
        {
            var a = new Blake2bMac(keySize, macSize);
            var b = Utilities.RandomBytes.Slice(0, keySize);

            Assert.Equal(keySize, a.KeySize);
            Assert.Equal(macSize, a.MacSize);

            using var k1 = Key.Import(a, b, KeyBlobFormat.RawSymmetricKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
            Assert.Equal(KeyExportPolicies.AllowPlaintextArchiving, k1.ExportPolicy);

            var n = k1.Export(KeyBlobFormat.NSecSymmetricKey);
            Assert.NotNull(n);

            using var k2 = Key.Import(a, n, KeyBlobFormat.NSecSymmetricKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var expected = b.ToArray();
            var actual = k2.Export(KeyBlobFormat.RawSymmetricKey);

            Assert.Equal(expected, actual);
        }

        #endregion

        #region Mac #1

        [Fact]
        public static void HashWithNullKey()
        {
            var a = MacAlgorithm.Blake2b_512;

            Assert.Throws<ArgumentNullException>("key", () => a.Mac(null!, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void HashWithWrongKey()
        {
            var a = MacAlgorithm.Blake2b_512;

            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("key", () => a.Mac(k, ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public static void HashWithKeySuccess()
        {
            var a = MacAlgorithm.Blake2b_512;

            using var k = new Key(a);

            var b = a.Mac(k, ReadOnlySpan<byte>.Empty);

            Assert.NotNull(b);
            Assert.Equal(a.MacSize, b.Length);
        }

        #endregion

        #region Mac #3

        [Fact]
        public static void HashWithSpanWithNullKey()
        {
            var a = MacAlgorithm.Blake2b_512;

            Assert.Throws<ArgumentNullException>("key", () => a.Mac(null!, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Fact]
        public static void HashWithSpanWithWrongKey()
        {
            var a = MacAlgorithm.Blake2b_512;

            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("key", () => a.Mac(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Fact]
        public static void HashWithSpanTooSmall()
        {
            var a = MacAlgorithm.Blake2b_512;

            using var k = new Key(a);

            Assert.Throws<ArgumentException>("mac", () => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize - 1]));
        }

        [Fact]
        public static void HashWithSpanTooLarge()
        {
            var a = MacAlgorithm.Blake2b_512;

            using var k = new Key(a);

            Assert.Throws<ArgumentException>("mac", () => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize + 1]));
        }

        [Fact]
        public static void HashWithSpanSuccess()
        {
            var a = MacAlgorithm.Blake2b_512;

            using var k = new Key(a);

            a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize]);
        }

        #endregion

        #region CreateKey

        [Fact]
        public static void CreateKey()
        {
            var a = MacAlgorithm.Blake2b_512;

            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

            var unexpected = new byte[actual.Length];
            Utilities.Fill(unexpected, actual[0]);

            Assert.NotEqual(unexpected, actual);
        }

        #endregion
    }
}
