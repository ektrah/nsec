using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class MacAlgorithmTests
    {
        public static readonly TheoryData<Type> MacAlgorithms = Registry.MacAlgorithms;
        public static readonly TheoryData<Type, int> MacAlgorithmsAndKeySizes = GetMacAlgorithmsAndKeySizes(Registry.MacAlgorithms);

        #region Properties

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.MinKeySize > 0);
            Assert.True(a.DefaultKeySize >= a.MinKeySize);
            Assert.True(a.MaxKeySize >= a.DefaultKeySize);

            Assert.True(a.MinMacSize > 0);
            Assert.True(a.DefaultMacSize >= a.MinMacSize);
            Assert.True(a.MaxMacSize >= a.DefaultMacSize);
        }

        #endregion

        #region Export #1

        [Theory]
        [MemberData(nameof(MacAlgorithmsAndKeySizes))]
        public static void ExportImportSymmetric(Type algorithmType, int keySize)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = Key.Import(a, Utilities.RandomBytes.Slice(0, keySize), KeyBlobFormat.RawSymmetricKey, KeyFlags.AllowExport))
            {
                Assert.Equal(KeyFlags.AllowExport, k.Flags);

                var b = k.Export(KeyBlobFormat.RawSymmetricKey);
                Assert.NotNull(b);
                Assert.Equal(b.Length, keySize);
            }
        }

        private static TheoryData<Type, int> GetMacAlgorithmsAndKeySizes(TheoryData<Type> algorithmTypes)
        {
            var data = new TheoryData<Type, int>();
            foreach (var algorithmType in algorithmTypes)
            {
                var a = (MacAlgorithm)Activator.CreateInstance((Type)algorithmType[0]);
                data.Add((Type)algorithmType[0], a.DefaultKeySize);
                data.Add((Type)algorithmType[0], a.MinKeySize);
                data.Add((Type)algorithmType[0], a.MaxKeySize);
            }
            return data;
        }

        #endregion

        #region Sign #1

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty));
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

                var expected = a.Sign(k, data);
                var actual = a.Sign(k, data);

                Assert.NotNull(actual);
                Assert.Equal(a.DefaultMacSize, actual.Length);
                Assert.Equal(expected, actual);
            }
        }

        #endregion

        #region Sign #2

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty, 0));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinMacSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.Throws<ArgumentOutOfRangeException>("macSize", () => a.Sign(k, ReadOnlySpan<byte>.Empty, a.MinMacSize - 1));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentOutOfRangeException>("macSize", () => a.Sign(k, ReadOnlySpan<byte>.Empty, a.MaxMacSize + 1));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountMinSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var data = Utilities.RandomBytes.Slice(0, 100);

                var expected = a.Sign(k, data, a.MinMacSize);
                var actual = a.Sign(k, data, a.MinMacSize);

                Assert.NotNull(actual);
                Assert.Equal(a.MinMacSize, actual.Length);
                Assert.Equal(expected, actual);
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountMaxSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var data = Utilities.RandomBytes.Slice(0, 100);

                var expected = a.Sign(k, data, a.MaxMacSize);
                var actual = a.Sign(k, data, a.MaxMacSize);

                Assert.NotNull(actual);
                Assert.Equal(a.MaxMacSize, actual.Length);
                Assert.Equal(expected, actual);
            }
        }

        #endregion

        #region Sign #3

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinMacSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.Throws<ArgumentException>("mac", () => a.Sign(k, ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize - 1]));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("mac", () => a.Sign(k, ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanMinSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var data = Utilities.RandomBytes.Slice(0, 100);

                var expected = new byte[a.MinMacSize];
                var actual = new byte[a.MinMacSize];

                a.Sign(k, data, expected);
                a.Sign(k, data, actual);
                Assert.Equal(expected, actual);
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanMaxSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var data = Utilities.RandomBytes.Slice(0, 100);

                var expected = new byte[a.MaxMacSize];
                var actual = new byte[a.MaxMacSize];

                a.Sign(k, data, expected);
                a.Sign(k, data, actual);
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

                var expected = new byte[a.DefaultMacSize];
                var actual = new Span<byte>(data, 0, a.DefaultMacSize);

                a.Sign(k, data, expected);
                a.Sign(k, data, actual);
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

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.TryVerify(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithSpanTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinMacSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.False(a.TryVerify(k, ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize - 1]));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithSpanTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.False(a.TryVerify(k, ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithSpanMinSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var d = ReadOnlySpan<byte>.Empty;

                var mac = a.Sign(k, d, a.MinMacSize);

                Assert.True(a.TryVerify(k, d, mac));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithSpanMaxSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var d = ReadOnlySpan<byte>.Empty;

                var mac = a.Sign(k, d, a.MaxMacSize);

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

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Verify(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinMacSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.Throws<ArgumentException>("mac", () => a.Verify(k, ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize - 1]));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("mac", () => a.Verify(k, ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanMinSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var d = ReadOnlySpan<byte>.Empty;

                var mac = a.Sign(k, d, a.MinMacSize);

                a.Verify(k, d, mac);
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithSpanMaxSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var d = ReadOnlySpan<byte>.Empty;

                var mac = a.Sign(k, d, a.MaxMacSize);

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

            using (var k = new Key(a, KeyFlags.AllowArchiving))
            {
                var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

                var unexpected = new byte[actual.Length];
                Utilities.Fill(unexpected, 0xDB);

                Assert.NotEqual(unexpected, actual);
            }
        }

        #endregion
    }
}
