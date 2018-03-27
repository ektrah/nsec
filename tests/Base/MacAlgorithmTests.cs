using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class MacAlgorithmTests
    {
        public static readonly TheoryData<Type> MacAlgorithms = Registry.MacAlgorithms;

        public static readonly TheoryData<Type, int, int> MacAlgorithmsAndSizes = new TheoryData<Type, int, int>
        {
            { typeof(Blake2bMac), 16, 16 },
            { typeof(Blake2bMac), 16, 32 },
            { typeof(Blake2bMac), 16, 64 },

            { typeof(Blake2bMac), 32, 16 },
            { typeof(Blake2bMac), 32, 32 },
            { typeof(Blake2bMac), 32, 64 },

            { typeof(Blake2bMac), 64, 16 },
            { typeof(Blake2bMac), 64, 32 },
            { typeof(Blake2bMac), 64, 64 },

            { typeof(HmacSha256), 32, 32 },

            { typeof(HmacSha512), 64, 64 },
        };

        #region Properties

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.KeySize > 0);
            Assert.True(a.MacSize > 0);
        }

        #endregion

        #region Export #1

        [Theory]
        [MemberData(nameof(MacAlgorithmsAndSizes))]
        public static void ExportImportRaw(Type algorithmType, int keySize, int macSize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType, keySize, macSize);
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
        [MemberData(nameof(MacAlgorithmsAndSizes))]
        public static void ExportImportNSec(Type algorithmType, int keySize, int macSize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType, keySize, macSize);
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
        public static void MacWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Mac(null, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("key", () => a.Mac(k, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithmsAndSizes))]
        public static void MacSuccess(Type algorithmType, int keySize, int macSize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType, keySize, macSize);

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
        public static void MacWithSpanWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Mac(null, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(SignatureAlgorithm.Ed25519))
            {
                Assert.Throws<ArgumentException>("key", () => a.Mac(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("mac", () => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void MacWithSpanTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("mac", () => a.Mac(k, ReadOnlySpan<byte>.Empty, new byte[a.MacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithmsAndSizes))]
        public static void MacWithSpanSuccess(Type algorithmType, int keySize, int macSize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType, keySize, macSize);

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
        public static void MacWithSpanOverlapping(Type algorithmType)
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
        [MemberData(nameof(MacAlgorithmsAndSizes))]
        public static void TryVerifyWithSpanSuccess(Type algorithmType, int keySize, int macSize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType, keySize, macSize);

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
        [MemberData(nameof(MacAlgorithmsAndSizes))]
        public static void VerifyWithSpanSuccess(Type algorithmType, int keySize, int macSize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType, keySize, macSize);

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
        [MemberData(nameof(MacAlgorithmsAndSizes))]
        public static void CreateKey(Type algorithmType, int keySize, int macSize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType, keySize, macSize);

            Assert.Equal(keySize, a.KeySize);
            Assert.Equal(macSize, a.MacSize);

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
