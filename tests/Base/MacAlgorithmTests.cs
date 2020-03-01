using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class MacAlgorithmTests
    {
        public static readonly TheoryData<MacAlgorithm> MacAlgorithms = Registry.MacAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void Properties(MacAlgorithm a)
        {
            Assert.True(a.KeySize > 0);
            Assert.True(a.MacSize > 0);
        }

        #endregion

        #region Export #1

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void ExportImportRaw(MacAlgorithm a)
        {
            var b = Utilities.RandomBytes.Slice(0, a.KeySize);

            using var k = Key.Import(a, b, KeyBlobFormat.RawSymmetricKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
            Assert.Equal(KeyExportPolicies.AllowPlaintextArchiving, k.ExportPolicy);

            var expected = b.ToArray();
            var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void ExportImportNSec(MacAlgorithm a)
        {
            var b = Utilities.RandomBytes.Slice(0, a.KeySize);

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

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithNullKey(MacAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("key", () => a.Mac(null!, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithDisposedKey(MacAlgorithm a)
        {
            var k = new Key(a);
            k.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.Mac(k, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithWrongKey(MacAlgorithm a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("key", () => a.Mac(k, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacSuccess(MacAlgorithm a)
        {
            using var k = new Key(a);
            var data = Utilities.RandomBytes.Slice(0, 100);

            var expected = a.Mac(k, data);
            var actual = a.Mac(k, data);

            Assert.NotNull(actual);
            Assert.Equal(a.MacSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Mac #3

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanWithNullKey(MacAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("key", () => a.Mac(null!, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanWithDisposedKey(MacAlgorithm a)
        {
            var k = new Key(a);
            k.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize]));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanWithWrongKey(MacAlgorithm a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("key", () => a.Mac(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanTooSmall(MacAlgorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("mac", () => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize - 1]));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanTooLarge(MacAlgorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("mac", () => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize + 1]));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanSuccess(MacAlgorithm a)
        {
            using var k = new Key(a);
            var data = Utilities.RandomBytes.Slice(0, 100);

            var expected = new byte[a.MacSize];
            var actual = new byte[a.MacSize];

            a.Mac(k, data, expected);
            a.Mac(k, data, actual);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanOverlapping(MacAlgorithm a)
        {
            using var k = new Key(a);
            var data = Utilities.RandomBytes.Slice(0, 100).ToArray();

            var expected = new byte[a.MacSize];
            var actual = data.AsSpan(0, a.MacSize);

            a.Mac(k, data, expected);
            a.Mac(k, data, actual);

            Assert.Equal(expected, actual.ToArray());
        }

        #endregion

        #region Verify

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithNullKey(MacAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("key", () => a.Verify(null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithDisposedKey(MacAlgorithm a)
        {
            var k = new Key(a);
            k.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.Verify(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize]));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithWrongKey(MacAlgorithm a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("key", () => a.Verify(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanTooSmall(MacAlgorithm a)
        {
            using var k = new Key(a);

            Assert.False(a.Verify(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize - 1]));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanTooLarge(MacAlgorithm a)
        {
            using var k = new Key(a);

            Assert.False(a.Verify(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize + 1]));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanSuccess(MacAlgorithm a)
        {
            using var k = new Key(a);
            var d = ReadOnlySpan<byte>.Empty;

            var mac = a.Mac(k, d);

            Assert.True(a.Verify(k, d, mac));
        }

        #endregion

        #region CreateKey

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void CreateKey(MacAlgorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
            Assert.Same(a, k.Algorithm);
            Assert.False(k.HasPublicKey);
            Assert.Throws<InvalidOperationException>(() => k.PublicKey);
            Assert.Equal(a.KeySize, k.Size);

            var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

            var unexpected = new byte[actual.Length];
            Utilities.Fill(unexpected, actual[0]);

            Assert.NotEqual(unexpected, actual);
        }

        #endregion
    }
}
