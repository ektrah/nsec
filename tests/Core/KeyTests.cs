using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Core
{
    public static class KeyTests
    {
        public static readonly TheoryData<Type> AsymmetricKeyAlgorithms = Registry.AsymmetricAlgorithms;
        public static readonly TheoryData<Type> SymmetricKeyAlgorithms = Registry.SymmetricAlgorithms;
        public static readonly TheoryData<Type> KeylessAlgorithms = Registry.KeylessAlgorithms;

        public static readonly TheoryData<Type, KeyBlobFormat> PublicKeyBlobFormats = Registry.PublicKeyBlobFormats;
        public static readonly TheoryData<Type, KeyBlobFormat> PrivateKeyBlobFormats = Registry.PrivateKeyBlobFormats;
        public static readonly TheoryData<Type, KeyBlobFormat> SymmetricKeyBlobFormats = Registry.SymmetricKeyBlobFormats;

        #region Properties

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void PropertiesAsymmetric(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.None))
            {
                Assert.Same(a, k.Algorithm);
                Assert.Equal(KeyFlags.None, k.Flags);
                Assert.NotNull(k.PublicKey);
                Assert.Same(a, k.PublicKey.Algorithm);
            }
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void PropertiesSymmetric(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.None))
            {
                Assert.Same(a, k.Algorithm);
                Assert.Equal(KeyFlags.None, k.Flags);
                Assert.Null(k.PublicKey);
            }
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void PropertiesAsymmetricAfterDispose(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            var k = new Key(a, KeyFlags.None);
            k.Dispose();
            Assert.Same(a, k.Algorithm);
            Assert.Equal(KeyFlags.None, k.Flags);
            Assert.NotNull(k.PublicKey);
            Assert.Same(a, k.PublicKey.Algorithm);
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void PropertiesSymmetricAfterDispose(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            var k = new Key(a, KeyFlags.None);
            k.Dispose();
            Assert.Same(a, k.Algorithm);
            Assert.Equal(KeyFlags.None, k.Flags);
            Assert.Null(k.PublicKey);
        }

        #endregion

        #region Ctor

        [Fact]
        public static void CtorWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => new Key(null));
        }

        [Theory]
        [MemberData(nameof(KeylessAlgorithms))]
        public static void CtorWithAlgorithmThatDoesNotUseKeys(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<NotSupportedException>(() => new Key(a));
        }

        #endregion

        #region Create

        [Fact]
        public static void CreateWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => Key.Create(null));
        }

        [Theory]
        [MemberData(nameof(KeylessAlgorithms))]
        public static void CreateWithAlgorithmThatDoesNotUseKeys(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<NotSupportedException>(() => Key.Create(a));
        }

        #endregion

        #region GetKeyBlobSize

        [Fact]
        public static void GetBlobSizeWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => Key.GetKeyBlobSize(null, KeyBlobFormat.None));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void GetBlobSizeWithFormatNone(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("format", () => Key.GetKeyBlobSize(a, KeyBlobFormat.None));
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void GetBlobSizeSuccess(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            var size = Key.GetKeyBlobSize(a, format);

            Assert.True(size != null);
            Assert.True(size > 0);
        }

        #endregion

        #region GetSupportedKeyBlobFormats

        [Fact]
        public static void GetBlobFormatsWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => Key.GetSupportedKeyBlobFormats(null));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void GetBlobFormatsSuccess(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            var formats = Key.GetSupportedKeyBlobFormats(a);

            Assert.True(formats.Length > 0);
        }

        #endregion

        #region Import

        [Fact]
        public static void ImportWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => Key.Import(null, ReadOnlySpan<byte>.Empty, KeyBlobFormat.None));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ImportWithFormatNone(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("format", () => Key.Import(a, ReadOnlySpan<byte>.Empty, KeyBlobFormat.None));
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        public static void ImportPrivateKeyEmpty(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<FormatException>(() => Key.Import(a, ReadOnlySpan<byte>.Empty, format));
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ImportSymmetricKeyEmpty(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<FormatException>(() => Key.Import(a, ReadOnlySpan<byte>.Empty, format));
        }

        #endregion

        #region TryImport

        [Fact]
        public static void TryImportWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => Key.TryImport(null, ReadOnlySpan<byte>.Empty, KeyBlobFormat.None, KeyFlags.None, out Key k));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void TryImportWithFormatNone(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("format", () => Key.TryImport(a, ReadOnlySpan<byte>.Empty, KeyBlobFormat.None, KeyFlags.None, out Key k));
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        public static void TryImportPrivateKeyEmpty(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.False(Key.TryImport(a, ReadOnlySpan<byte>.Empty, format, KeyFlags.None, out Key k));
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void TryImportSymmetricKeyEmpty(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            Assert.False(Key.TryImport(a, ReadOnlySpan<byte>.Empty, format, KeyFlags.None, out Key k));
        }

        #endregion

        #region Export #1

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ExportWithFormatNone(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.None))
            {
                Assert.Equal(KeyFlags.None, k.Flags);

                Assert.Throws<ArgumentException>("format", () => k.Export(KeyBlobFormat.None));
            }
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        public static void ExportPublicKey(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.None))
            {
                Assert.Equal(KeyFlags.None, k.Flags);

                Assert.NotNull(k.Export(format));
                Assert.NotNull(k.Export(format));
                Assert.NotNull(k.Export(format));
            }
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        public static void ExportPrivateKeyNotAllowed(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.None))
            {
                Assert.Equal(KeyFlags.None, k.Flags);

                Assert.Throws<InvalidOperationException>(() => k.Export(format));
                Assert.Throws<InvalidOperationException>(() => k.Export(format));
                Assert.Throws<InvalidOperationException>(() => k.Export(format));
            }
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ExportSymmetricKeyNotAllowed(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.None))
            {
                Assert.Equal(KeyFlags.None, k.Flags);

                Assert.Throws<InvalidOperationException>(() => k.Export(format));
                Assert.Throws<InvalidOperationException>(() => k.Export(format));
                Assert.Throws<InvalidOperationException>(() => k.Export(format));
            }
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        public static void ExportPrivateKeyExportAllowed(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.AllowExport))
            {
                Assert.Equal(KeyFlags.AllowExport, k.Flags);

                Assert.NotNull(k.Export(format));
                Assert.NotNull(k.Export(format));
                Assert.NotNull(k.Export(format));
            }
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ExportSymmetricKeyExportAllowed(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.AllowExport))
            {
                Assert.Equal(KeyFlags.AllowExport, k.Flags);

                Assert.NotNull(k.Export(format));
                Assert.NotNull(k.Export(format));
                Assert.NotNull(k.Export(format));
            }
        }

        [Theory]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        public static void ExportPrivateKeyArchivingAllowed(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.AllowArchiving))
            {
                Assert.Equal(KeyFlags.AllowArchiving, k.Flags);

                Assert.NotNull(k.Export(format));
                Assert.Throws<InvalidOperationException>(() => k.Export(format));
                Assert.Throws<InvalidOperationException>(() => k.Export(format));
            }
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ExportSymmetricKeyArchivingAllowed(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.AllowArchiving))
            {
                Assert.Equal(KeyFlags.AllowArchiving, k.Flags);

                Assert.NotNull(k.Export(format));
                Assert.Throws<InvalidOperationException>(() => k.Export(format));
                Assert.Throws<InvalidOperationException>(() => k.Export(format));
            }
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void ExportPublicKeyAfterDispose(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            var k = new Key(a, KeyFlags.None);
            k.Dispose();

            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPublicKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPublicKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPublicKey));
        }

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        public static void ExportPrivateKeyExportAllowedAfterDispose(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            var k = new Key(a, KeyFlags.AllowExport);
            k.Dispose();

            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPrivateKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPrivateKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawPrivateKey));
        }

        [Theory]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ExportSymmetricKeyExportAllowedAfterDispose(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            var k = new Key(a, KeyFlags.AllowExport);
            k.Dispose();

            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawSymmetricKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawSymmetricKey));
            Assert.Throws<ObjectDisposedException>(() => k.Export(KeyBlobFormat.RawSymmetricKey));
        }

        #endregion

        #region Export #2

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void ExportWithSpanWithFormatNone(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.None))
            {
                Assert.Equal(KeyFlags.None, k.Flags);

                Assert.Throws<ArgumentException>("format", () => k.Export(KeyBlobFormat.None, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(PublicKeyBlobFormats))]
        [MemberData(nameof(PrivateKeyBlobFormats))]
        [MemberData(nameof(SymmetricKeyBlobFormats))]
        public static void ExportWithSpanTooSmall(Type algorithmType, KeyBlobFormat format)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.AllowExport))
            {
                Assert.Equal(KeyFlags.AllowExport, k.Flags);

                Assert.Throws<ArgumentException>("blob", () => k.Export(format, Span<byte>.Empty));
            }
        }

        #endregion

        #region Dispose

        [Theory]
        [MemberData(nameof(AsymmetricKeyAlgorithms))]
        [MemberData(nameof(SymmetricKeyAlgorithms))]
        public static void DisposeMoreThanOnce(Type algorithmType)
        {
            var a = (Algorithm)Activator.CreateInstance(algorithmType);

            var k = new Key(a);
            k.Dispose();
            k.Dispose();
            k.Dispose();
        }

        #endregion
    }
}
