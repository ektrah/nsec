using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class MacAlgorithmTests
    {
        public static readonly TheoryData<Type> MacAlgorithms = Registry.MacAlgorithms;

        public static readonly TheoryData<Type, int> MacAlgorithmsAndKeySizes = new TheoryData<Type, int>
        {
            { typeof(HmacSha256),  32 }, // L
            { typeof(HmacSha256),  48 },
            { typeof(HmacSha256),  64 }, // B
            { typeof(HmacSha256),  80 },
            { typeof(HmacSha256),  96 },

            { typeof(HmacSha512),  64 }, // L
            { typeof(HmacSha512),  96 },
            { typeof(HmacSha512), 128 }, // B
            { typeof(HmacSha512), 160 },
            { typeof(HmacSha512), 192 },

            { typeof(Blake2bMac),  16 },
            { typeof(Blake2bMac),  24 },
            { typeof(Blake2bMac),  32 },
            { typeof(Blake2bMac),  48 },
            { typeof(Blake2bMac),  64 },
        };

        #region Properties

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.MinKeySize >= 0);
            Assert.True(a.DefaultKeySize > 0);
            Assert.True(a.DefaultKeySize >= a.MinKeySize);
            Assert.True(a.MaxKeySize >= a.DefaultKeySize);

            Assert.True(a.MacSize > 0);
        }

        #endregion

        #region Export #1

        [Theory]
        [MemberData(nameof(MacAlgorithmsAndKeySizes))]
        public static void ExportImportRaw(Type algorithmType, int keySize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);
            var b = Utilities.RandomBytes.Slice(0, keySize);

            using (var k = Key.Import(a, b, KeyBlobFormat.RawSymmetricKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving }))
            {
                Assert.Equal(KeyExportPolicies.AllowPlaintextArchiving, k.ExportPolicy);

                var expected = b.ToArray();
                var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

                Assert.Equal(expected, actual);
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithmsAndKeySizes))]
        public static void ExportImportNSec(Type algorithmType, int keySize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);
            var b = Utilities.RandomBytes.Slice(0, keySize);

            using (var k1 = Key.Import(a, b, KeyBlobFormat.RawSymmetricKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving }))
            {
                Assert.Equal(KeyExportPolicies.AllowPlaintextArchiving, k1.ExportPolicy);

                var n = k1.Export(KeyBlobFormat.NSecSymmetricKey);
                Assert.NotNull(n);

                using (var k2 = Key.Import(a, n, KeyBlobFormat.NSecSymmetricKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving }))
                {
                    var expected = b.ToArray();
                    var actual = k2.Export(KeyBlobFormat.RawSymmetricKey);

                    Assert.Equal(expected, actual);
                }
            }
        }

        #endregion

        #region Mac #1

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Mac(null, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("key", () => a.Mac(k, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var data = Utilities.RandomBytes.Slice(0, 100);

                var expected = a.Mac(k, data);
                var actual = a.Mac(k, data);

                Assert.NotNull(actual);
                Assert.Equal(a.MacSize, actual.Length);
                Assert.Equal(expected, actual);
            }
        }

        #endregion

        #region Mac #3

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Mac(null, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("key", () => a.Mac(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("mac", () => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("mac", () => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var data = Utilities.RandomBytes.Slice(0, 100);

                var expected = new byte[a.MacSize];
                var actual = new byte[a.MacSize];

                a.Mac(k, data, expected);
                a.Mac(k, data, actual);
                Assert.Equal(expected, actual);
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanOverlapping(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var data = Utilities.RandomBytes.Slice(0, 100).ToArray();

                var expected = new byte[a.MacSize];
                var actual = data.AsSpan(0, a.MacSize);

                a.Mac(k, data, expected);
                a.Mac(k, data, actual);

                Assert.Equal(expected, actual.ToArray());
            }
        }

        #endregion

        #region TryVerify

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.TryVerify(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("key", () => a.TryVerify(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithSpanTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.False(a.TryVerify(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithSpanTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.False(a.TryVerify(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithSpanSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var d = ReadOnlySpan<byte>.Empty;

                var mac = a.Mac(k, d);

                Assert.True(a.TryVerify(k, d, mac));
            }
        }

        #endregion

        #region Verify

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Verify(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("key", () => a.Verify(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<CryptographicException>(() => a.Verify(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<CryptographicException>(() => a.Verify(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var d = ReadOnlySpan<byte>.Empty;

                var mac = a.Mac(k, d);

                a.Verify(k, d, mac);
            }
        }

        #endregion

        #region CreateKey

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void CreateKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving }))
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
