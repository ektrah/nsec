using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Core
{
    public static class KeyTests
    {
        public static readonly TheoryData<Algorithm> AsymmetricKeyAlgorithms = Registry.AsymmetricAlgorithms;
        public static readonly TheoryData<Algorithm> SymmetricKeyAlgorithms = Registry.SymmetricAlgorithms;
        public static readonly TheoryData<Algorithm> KeylessAlgorithms = Registry.KeylessAlgorithms;

        public static readonly TheoryData<Algorithm, KeyBlobFormat> PublicKeyBlobFormats = Registry.PublicKeyBlobFormats;
        public static readonly TheoryData<Algorithm, KeyBlobFormat> PrivateKeyBlobFormats = Registry.PrivateKeyBlobFormats;
        public static readonly TheoryData<Algorithm, KeyBlobFormat> SymmetricKeyBlobFormats = Registry.SymmetricKeyBlobFormats;

        #region Properties

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void PropertiesAsymmetric(Algorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.Same(a, k.Algorithm);
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);
            Assert.True(k.HasPublicKey);
            Assert.NotNull(k.PublicKey);
            Assert.Same(a, k.PublicKey.Algorithm);
            Assert.True(k.PublicKey.Size > 0);
            Assert.True(k.Size > 0);
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void PropertiesSymmetric(Algorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.Same(a, k.Algorithm);
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);
            Assert.False(k.HasPublicKey);
            Assert.Throws<InvalidOperationException>(() => k.PublicKey);
            Assert.True(k.Size > 0);
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void PropertiesAsymmetricAfterDispose(Algorithm a)
        {
            var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            k.Dispose();
            Assert.Same(a, k.Algorithm);
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);
            Assert.NotNull(k.PublicKey);
            Assert.Same(a, k.PublicKey.Algorithm);
            Assert.True(k.PublicKey.Size > 0);
            Assert.True(k.Size > 0);
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void PropertiesSymmetricAfterDispose(Algorithm a)
        {
            var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            k.Dispose();
            Assert.Same(a, k.Algorithm);
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);
            Assert.False(k.HasPublicKey);
            Assert.Throws<InvalidOperationException>(() => k.PublicKey);
            Assert.True(k.Size > 0);
        }

        #endregion

        #region Ctor

        [Fact]
        public static void CtorWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => new Key(null!));
        }

        [Theory]
        [MemberData(nameof(KeylessAlgorithms))]
        public static void CtorWithAlgorithmThatDoesNotUseKeys(Algorithm a)
        {
            Assert.Throws<NotSupportedException>(() => new Key(a));
        }

        #endregion

        #region Create

        [Fact]
        public static void CreateWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => Key.Create(null!));
        }

        [Theory]
        [MemberData(nameof(KeylessAlgorithms))]
        public static void CreateWithAlgorithmThatDoesNotUseKeys(Algorithm a)
        {
            Assert.Throws<NotSupportedException>(() => Key.Create(a));
        }

        #endregion

        #region Import

        [Fact]
        public static void ImportWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => Key.Import(null!, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ImportWithFormatMin(Algorithm a)
        {
            Assert.Throws<ArgumentException>("format", () => Key.Import(a, ReadOnlySpan<byte>.Empty, (KeyBlobFormat)int.MinValue));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ImportWithFormatMax(Algorithm a)
        {
            Assert.Throws<ArgumentException>("format", () => Key.Import(a, ReadOnlySpan<byte>.Empty, (KeyBlobFormat)int.MaxValue));
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        public static void ImportPrivateKeyEmpty(Algorithm a, KeyBlobFormat format)
        {
            Assert.Throws<FormatException>(() => Key.Import(a, ReadOnlySpan<byte>.Empty, format));
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ImportSymmetricKeyEmpty(Algorithm a, KeyBlobFormat format)
        {
            Assert.Throws<FormatException>(() => Key.Import(a, ReadOnlySpan<byte>.Empty, format));
        }

        #endregion

        #region TryImport

        [Fact]
        public static void TryImportWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => Key.TryImport(null!, ReadOnlySpan<byte>.Empty, 0, out var k, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None }));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void TryImportWithFormatMin(Algorithm a)
        {
            Assert.Throws<ArgumentException>("format", () => Key.TryImport(a, ReadOnlySpan<byte>.Empty, (KeyBlobFormat)int.MinValue, out var k, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None }));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void TryImportWithFormatMax(Algorithm a)
        {
            Assert.Throws<ArgumentException>("format", () => Key.TryImport(a, ReadOnlySpan<byte>.Empty, (KeyBlobFormat)int.MaxValue, out var k, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None }));
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        public static void TryImportPrivateKeyEmpty(Algorithm a, KeyBlobFormat format)
        {
            Assert.False(Key.TryImport(a, ReadOnlySpan<byte>.Empty, format, out _, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None }));
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void TryImportSymmetricKeyEmpty(Algorithm a, KeyBlobFormat format)
        {
            Assert.False(Key.TryImport(a, ReadOnlySpan<byte>.Empty, format, out _, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None }));
        }

        #endregion

        #region Export

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ExportWithFormatMin(Algorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, k.ExportPolicy);

            Assert.Throws<ArgumentException>("format", () => k.Export((KeyBlobFormat)int.MinValue));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ExportWithFormatMax(Algorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);

            Assert.Throws<ArgumentException>("format", () => k.Export((KeyBlobFormat)int.MaxValue));
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void ExportPublicKey(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);

            Assert.NotNull(k.Export(format));
            Assert.NotNull(k.Export(format));
            Assert.NotNull(k.Export(format));
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ExportKeyNotAllowed(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);

            Assert.Throws<InvalidOperationException>(() => k.Export(format));
            Assert.Throws<InvalidOperationException>(() => k.Export(format));
            Assert.Throws<InvalidOperationException>(() => k.Export(format));
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ExportKeyExportAllowed(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, k.ExportPolicy);

            Assert.NotNull(k.Export(format));
            Assert.NotNull(k.Export(format));
            Assert.NotNull(k.Export(format));
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ExportPrivateKeyArchivingAllowed(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
            Assert.Equal(KeyExportPolicies.AllowPlaintextArchiving, k.ExportPolicy);

            Assert.NotNull(k.Export(format));
            Assert.Throws<InvalidOperationException>(() => k.Export(format));
            Assert.Throws<InvalidOperationException>(() => k.Export(format));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void ExportPublicKeyAfterDispose(Algorithm a)
        {
            var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            k.Dispose();

            k.Export(KeyBlobFormat.RawPublicKey);
            k.Export(KeyBlobFormat.RawPublicKey);
            k.Export(KeyBlobFormat.RawPublicKey);
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void ExportPrivateKeyExportAllowedAfterDispose(Algorithm a)
        {
            var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            k.Dispose();

            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPrivateKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPrivateKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPrivateKey));
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ExportSymmetricKeyExportAllowedAfterDispose(Algorithm a)
        {
            var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            k.Dispose();

            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawSymmetricKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawSymmetricKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawSymmetricKey));
        }

        #endregion

        #region Dispose

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void DisposeMoreThanOnce(Algorithm a)
        {
            var k = new Key(a);
            k.Dispose();
            k.Dispose();
            k.Dispose();
        }

        #endregion

        #region GetExportBlobSize


        [Theory]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        public static void GetExportBlobSize(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

            var b = k.Export(format);
            Assert.NotNull(b);

            var blobSize = k.GetExportBlobSize(format);
            Assert.Equal(b.Length, blobSize);
        }

        #endregion

        #region TryExport

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void TryExportWithFormatMin(Algorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, k.ExportPolicy);

            Assert.Throws<ArgumentException>("format", () => k.TryExport((KeyBlobFormat)int.MinValue, Span<byte>.Empty, out _));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void TryExportWithFormatMax(Algorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);

            Assert.Throws<ArgumentException>("format", () => k.TryExport((KeyBlobFormat)int.MaxValue, Span<byte>.Empty, out _));
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void TryExportPublicKey(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);

            var expected = k.GetExportBlobSize(format);
            var b = new byte[expected + 100];

            Assert.True(k.TryExport(format, b, out var actual));
            Assert.Equal(expected, actual);

            Assert.True(k.TryExport(format, b, out actual));
            Assert.Equal(expected, actual);

            Assert.True(k.TryExport(format, b, out actual));
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void TryExportKeyNotAllowed(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            Assert.Equal(KeyExportPolicies.None, k.ExportPolicy);

            var expected = k.GetExportBlobSize(format);
            var b = new byte[expected + 100];

            Assert.Throws<InvalidOperationException>(() => k.TryExport(format, b, out _));
            Assert.Throws<InvalidOperationException>(() => k.TryExport(format, b, out _));
            Assert.Throws<InvalidOperationException>(() => k.TryExport(format, b, out _));
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void TryExportKeyExportAllowed(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, k.ExportPolicy);

            var expected = k.GetExportBlobSize(format);
            var b = new byte[expected + 100];

            Assert.True(k.TryExport(format, b, out var actual));
            Assert.Equal(expected, actual);

            Assert.True(k.TryExport(format, b, out actual));
            Assert.Equal(expected, actual);

            Assert.True(k.TryExport(format, b, out actual));
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void TryExportPrivateKeyArchivingAllowed(Algorithm a, KeyBlobFormat format)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
            Assert.Equal(KeyExportPolicies.AllowPlaintextArchiving, k.ExportPolicy);

            var expected = k.GetExportBlobSize(format);
            var b = new byte[expected + 100];

            Assert.True(k.TryExport(format, b, out var actual));
            Assert.Equal(expected, actual);

            Assert.Throws<InvalidOperationException>(() => k.TryExport(format, b, out _));
            Assert.Throws<InvalidOperationException>(() => k.TryExport(format, b, out _));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void TryExportPublicKeyAfterDispose(Algorithm a)
        {
            var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            k.Dispose();

            var expected = k.GetExportBlobSize(KeyBlobFormat.RawPublicKey);
            var b = new byte[expected + 100];

            k.TryExport(KeyBlobFormat.RawPublicKey, b, out var actual);
            Assert.Equal(expected, actual);

            k.TryExport(KeyBlobFormat.RawPublicKey, b, out actual);
            Assert.Equal(expected, actual);

            k.TryExport(KeyBlobFormat.RawPublicKey, b, out actual);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void TryExportPrivateKeyExportAllowedAfterDispose(Algorithm a)
        {
            var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            k.Dispose();

            Assert.Throws<ObjectDisposedException>(() => k.TryExport(KeyBlobFormat.RawPrivateKey, Span<byte>.Empty, out _));
            Assert.Throws<ObjectDisposedException>(() => k.TryExport(KeyBlobFormat.RawPrivateKey, Span<byte>.Empty, out _));
            Assert.Throws<ObjectDisposedException>(() => k.TryExport(KeyBlobFormat.RawPrivateKey, Span<byte>.Empty, out _));
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void TryExportSymmetricKeyExportAllowedAfterDispose(Algorithm a)
        {
            var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            k.Dispose();

            Assert.Throws<ObjectDisposedException>(() => k.TryExport(KeyBlobFormat.RawSymmetricKey, Span<byte>.Empty, out _));
            Assert.Throws<ObjectDisposedException>(() => k.TryExport(KeyBlobFormat.RawSymmetricKey, Span<byte>.Empty, out _));
            Assert.Throws<ObjectDisposedException>(() => k.TryExport(KeyBlobFormat.RawSymmetricKey, Span<byte>.Empty, out _));
        }

        #endregion
    }
}
