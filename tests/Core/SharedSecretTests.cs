using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Core
{
    public static class SharedSecretTests
    {
        public static readonly TheoryData<SharedSecretBlobFormat> SharedSecretBlobFormats = Registry.SharedSecretBlobFormats;

        #region Import

        [Fact]
        public static void ImportEmpty()
        {
            using var s = SharedSecret.Import([], SharedSecretBlobFormat.RawSharedSecret);
            Assert.NotNull(s);
            Assert.Equal(0, s.Size);
        }

        [Fact]
        public static void ImportNonEmpty()
        {
            var b = Utilities.RandomBytes[..57];

            using var s = SharedSecret.Import(b, SharedSecretBlobFormat.RawSharedSecret);
            Assert.NotNull(s);
            Assert.Equal(b.Length, s.Size);
        }

        [Fact]
        public static void ImportZeros()
        {
            var b = new byte[64];

            using var s = SharedSecret.Import(b, SharedSecretBlobFormat.RawSharedSecret);
            Assert.NotNull(s);
            Assert.Equal(b.Length, s.Size);
        }

        [Fact]
        public static void ImportTooLong()
        {
            var b = new byte[129];

            Assert.Throws<FormatException>(() => SharedSecret.Import(b, SharedSecretBlobFormat.RawSharedSecret));
        }

        #endregion

        #region Dispose

        [Fact]
        public static void DisposeMoreThanOnce()
        {
            var b = Utilities.RandomBytes[..64];
            var s = SharedSecret.Import(b, SharedSecretBlobFormat.RawSharedSecret);
            Assert.NotNull(s);
            s.Dispose();
            s.Dispose();
            s.Dispose();
        }

        [Fact]
        public static void PropertiesAfterDispose()
        {
            var b = Utilities.RandomBytes[..64];
            var s = SharedSecret.Import(b, SharedSecretBlobFormat.RawSharedSecret);
            s.Dispose();
            Assert.NotNull(s);
            Assert.Equal(b.Length, s.Size);
        }

        #endregion

        #region Import

        [Fact]
        public static void ImportWithFormatMin()
        {
            Assert.Throws<ArgumentException>("format", () => SharedSecret.Import([], (SharedSecretBlobFormat)int.MinValue));
        }

        [Fact]
        public static void ImportWithFormatMax()
        {
            Assert.Throws<ArgumentException>("format", () => SharedSecret.Import([], (SharedSecretBlobFormat)int.MaxValue));
        }

        #endregion

        #region TryImport

        [Fact]
        public static void TryImportWithFormatMin()
        {
            Assert.Throws<ArgumentException>("format", () => SharedSecret.TryImport([], (SharedSecretBlobFormat)int.MinValue, out _));
        }

        [Fact]
        public static void TryImportWithFormatMax()
        {
            Assert.Throws<ArgumentException>("format", () => SharedSecret.TryImport([], (SharedSecretBlobFormat)int.MaxValue, out _));
        }

        #endregion

        #region Export

        [Fact]
        public static void ExportWithFormatMin()
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, s.ExportPolicy);

            Assert.Throws<ArgumentException>("format", () => s.Export((SharedSecretBlobFormat)int.MinValue));
        }

        [Fact]
        public static void ExportWithFormatMax()
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, s.ExportPolicy);

            Assert.Throws<ArgumentException>("format", () => s.Export((SharedSecretBlobFormat)int.MaxValue));
        }

        [Theory]
        [MemberData(nameof(SharedSecretBlobFormats))]
        public static void ExportKeyNotAllowed(SharedSecretBlobFormat format)
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.None });
            Assert.Equal(KeyExportPolicies.None, s.ExportPolicy);

            Assert.Throws<InvalidOperationException>(() => s.Export(format));
            Assert.Throws<InvalidOperationException>(() => s.Export(format));
            Assert.Throws<InvalidOperationException>(() => s.Export(format));
        }

        [Theory]
        [MemberData(nameof(SharedSecretBlobFormats))]
        public static void ExportKeyExportAllowed(SharedSecretBlobFormat format)
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, s.ExportPolicy);

            Assert.NotNull(s.Export(format));
            Assert.NotNull(s.Export(format));
            Assert.NotNull(s.Export(format));
        }

        [Fact]
        public static void ExportAllowedAfterDispose()
        {
            var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            s.Dispose();

            Assert.Throws<ObjectDisposedException>(() => s.Export(SharedSecretBlobFormat.RawSharedSecret));
            Assert.Throws<ObjectDisposedException>(() => s.Export(SharedSecretBlobFormat.RawSharedSecret));
            Assert.Throws<ObjectDisposedException>(() => s.Export(SharedSecretBlobFormat.RawSharedSecret));
        }

        #endregion

        #region GetExportBlobSize

        [Theory]
        [MemberData(nameof(SharedSecretBlobFormats))]
        public static void GetExportBlobSize(SharedSecretBlobFormat format)
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

            var b = s.Export(format);
            Assert.NotNull(b);

            var blobSize = s.GetExportBlobSize(format);
            Assert.Equal(b.Length, blobSize);
        }

        #endregion

        #region TryExport

        [Fact]
        public static void TryExportWithFormatMin()
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, s.ExportPolicy);

            Assert.Throws<ArgumentException>("format", () => s.TryExport((SharedSecretBlobFormat)int.MinValue, [], out _));
        }

        [Fact]
        public static void TryExportWithFormatMax()
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, s.ExportPolicy);

            Assert.Throws<ArgumentException>("format", () => s.TryExport((SharedSecretBlobFormat)int.MaxValue, [], out _));
        }

        [Theory]
        [MemberData(nameof(SharedSecretBlobFormats))]
        public static void TryExportKeyNotAllowed(SharedSecretBlobFormat format)
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.None });
            Assert.Equal(KeyExportPolicies.None, s.ExportPolicy);

            var expected = s.GetExportBlobSize(format);
            var b = new byte[expected + 100];

            Assert.Throws<InvalidOperationException>(() => s.TryExport(format, b, out _));
            Assert.Throws<InvalidOperationException>(() => s.TryExport(format, b, out _));
            Assert.Throws<InvalidOperationException>(() => s.TryExport(format, b, out _));
        }

        [Theory]
        [MemberData(nameof(SharedSecretBlobFormats))]
        public static void TryExportKeyExportAllowed(SharedSecretBlobFormat format)
        {
            using var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Assert.Equal(KeyExportPolicies.AllowPlaintextExport, s.ExportPolicy);

            var expected = s.GetExportBlobSize(format);
            var b = new byte[expected + 100];

            Assert.True(s.TryExport(format, b, out var actual));
            Assert.Equal(expected, actual);

            Assert.True(s.TryExport(format, b, out actual));
            Assert.Equal(expected, actual);

            Assert.True(s.TryExport(format, b, out actual));
            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void TryExportAllowedAfterDispose()
        {
            var s = SharedSecret.Import(Utilities.RandomBytes[..64], SharedSecretBlobFormat.RawSharedSecret, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            s.Dispose();

            Assert.Throws<ObjectDisposedException>(() => s.TryExport(SharedSecretBlobFormat.RawSharedSecret, [], out _));
            Assert.Throws<ObjectDisposedException>(() => s.TryExport(SharedSecretBlobFormat.RawSharedSecret, [], out _));
            Assert.Throws<ObjectDisposedException>(() => s.TryExport(SharedSecretBlobFormat.RawSharedSecret, [], out _));
        }

        #endregion
    }
}
