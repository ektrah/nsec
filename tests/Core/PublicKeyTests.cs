using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Core
{
    public static class PublicKeyTests
    {
        public static readonly TheoryData<Algorithm> AsymmetricKeyAlgorithms = Registry.AsymmetricAlgorithms;
        public static readonly TheoryData<Algorithm, KeyBlobFormat> PublicKeyBlobFormats = Registry.PublicKeyBlobFormats;

        #region Import

        [Fact]
        public static void ImportWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => PublicKey.Import(null!, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void ImportWithFormatMin(Algorithm a)
        {
            Assert.Throws<ArgumentException>("format", () => PublicKey.Import(a, ReadOnlySpan<byte>.Empty, (KeyBlobFormat)int.MinValue));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void ImportWithFormatMax(Algorithm a)
        {
            Assert.Throws<ArgumentException>("format", () => PublicKey.Import(a, ReadOnlySpan<byte>.Empty, (KeyBlobFormat)int.MaxValue));
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void ImportEmpty(Algorithm a, KeyBlobFormat format)
        {
            Assert.Throws<FormatException>(() => PublicKey.Import(a, ReadOnlySpan<byte>.Empty, format));
        }

        #endregion

        #region TryImport

        [Fact]
        public static void TryImportWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => PublicKey.TryImport(null!, ReadOnlySpan<byte>.Empty, 0, out var pk));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void TryImportWithFormatMin(Algorithm a)
        {
            Assert.Throws<ArgumentException>("format", () => PublicKey.TryImport(a, ReadOnlySpan<byte>.Empty, (KeyBlobFormat)int.MinValue, out var pk));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void TryImportWithFormatMax(Algorithm a)
        {
            Assert.Throws<ArgumentException>("format", () => PublicKey.TryImport(a, ReadOnlySpan<byte>.Empty, (KeyBlobFormat)int.MaxValue, out var pk));
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void TryImportEmpty(Algorithm a, KeyBlobFormat format)
        {
            Assert.False(PublicKey.TryImport(a, ReadOnlySpan<byte>.Empty, format, out var pk));
            Assert.Null(pk);
        }

        #endregion

        #region Equals

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void EqualAndSame(Algorithm a)
        {
            using var k = new Key(a);
            Assert.Same(k.PublicKey, k.PublicKey);
            Assert.True(k.PublicKey.Equals(k.PublicKey));
            Assert.True(k.PublicKey.Equals((object)k.PublicKey));
            Assert.Equal(k.PublicKey.GetHashCode(), k.PublicKey.GetHashCode());
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void EqualButNotSame(Algorithm a)
        {
            using var k = new Key(a);

            var b = k.Export(KeyBlobFormat.RawPublicKey);

            var pk1 = PublicKey.Import(a, b, KeyBlobFormat.RawPublicKey);
            var pk2 = PublicKey.Import(a, b, KeyBlobFormat.RawPublicKey);

            Assert.NotSame(pk1, pk2);
            Assert.True(pk1.Equals(pk2));
            Assert.True(pk1.Equals((object)pk2));
            Assert.Equal(pk1.GetHashCode(), pk2.GetHashCode());
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void EqualNull(Algorithm a)
        {
            using (var k = new Key(a))
            {
                Assert.False(k.PublicKey.Equals((PublicKey?)null));
            }

            using (var k = new Key(a))
            {
                Assert.False(k.PublicKey.Equals((object?)null));
            }
        }

        #endregion

        #region Export

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void ExportWithFormatMin(Algorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("format", () => k.PublicKey.Export((KeyBlobFormat)int.MinValue));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void ExportWithFormatMax(Algorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("format", () => k.PublicKey.Export((KeyBlobFormat)int.MaxValue));
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void ExportPublicKey(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a);

            var b = k.PublicKey.Export(format);
            Assert.NotNull(b);

            var pk = PublicKey.Import(a, b, format);
            Assert.NotNull(pk);
            Assert.Equal(k.PublicKey, pk);
            Assert.Same(a, pk.Algorithm);
        }

        #endregion

        #region GetExportBlobSize

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void GetExportBlobSize(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a);

            var b = k.PublicKey.Export(format);
            Assert.NotNull(b);

            var blobSize = k.PublicKey.GetExportBlobSize(format);
            Assert.Equal(b.Length, blobSize);
        }

        #endregion

        #region TryExport

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void TryExportWithFormatMin(Algorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("format", () => k.PublicKey.TryExport((KeyBlobFormat)int.MinValue, Span<byte>.Empty, out _));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void TryExportWithFormatMax(Algorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("format", () => k.PublicKey.TryExport((KeyBlobFormat)int.MaxValue, Span<byte>.Empty, out _));
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void TryExportSmaller(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a);

            Assert.False(k.PublicKey.TryExport(format, Span<byte>.Empty, out _));
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void TryExportExact(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a);

            var expected = k.PublicKey.GetExportBlobSize(format);
            var b = new byte[expected + 0];
            Assert.True(k.PublicKey.TryExport(format, b, out var actual));
            Assert.Equal(expected, actual);

            var pk = PublicKey.Import(a, b, format);
            Assert.NotNull(pk);
            Assert.Equal(k.PublicKey, pk);
            Assert.Same(a, pk.Algorithm);
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void TryExportLarger(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a);

            var expected = k.PublicKey.GetExportBlobSize(format);
            var b = new byte[expected + 100];
            Assert.True(k.PublicKey.TryExport(format, b, out var actual));
            Assert.Equal(expected, actual);

            var pk = PublicKey.Import(a, new ReadOnlySpan<byte>(b, 0, actual), format);
            Assert.NotNull(pk);
            Assert.Equal(k.PublicKey, pk);
            Assert.Same(a, pk.Algorithm);
        }

        #endregion
    }
}
