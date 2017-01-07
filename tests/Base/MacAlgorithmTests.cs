using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class MacAlgorithmTests
    {
        public static readonly TheoryData<Type> MacAlgorithms = Registry.MacAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.MinKeySize > 0);
            Assert.True(a.DefaultKeySize >= a.MinKeySize);
            Assert.True(a.MaxKeySize >= a.DefaultKeySize);

            Assert.True(a.MinNonceSize >= 0);
            Assert.True(a.MaxNonceSize >= a.MinNonceSize);

            Assert.True(a.MinMacSize > 0);
            Assert.True(a.DefaultMacSize >= a.MinMacSize);
            Assert.True(a.MaxMacSize >= a.DefaultMacSize);
        }

        #endregion

        #region Sign #1

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithNonceTooShort(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinNonceSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.Throws<ArgumentException>("nonce", () => a.Sign(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithNonceTooLong(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Sign(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignEmptySuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var b = a.Sign(k, new byte[a.MinNonceSize], ReadOnlySpan<byte>.Empty);

                Assert.NotNull(b);
                Assert.Equal(a.DefaultMacSize, b.Length);
            }
        }

        #endregion

        #region Sign #2

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountWithNonceTooShort(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinNonceSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.Throws<ArgumentException>("nonce", () => a.Sign(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, 0));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountWithNonceTooLong(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Sign(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, 0));
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
                    Assert.Throws<ArgumentOutOfRangeException>("macSize", () => a.Sign(k, new byte[a.MinNonceSize], ReadOnlySpan<byte>.Empty, a.MinMacSize - 1));
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
                Assert.Throws<ArgumentOutOfRangeException>("macSize", () => a.Sign(k, new byte[a.MinNonceSize], ReadOnlySpan<byte>.Empty, a.MaxMacSize + 1));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountMinSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var b = a.Sign(k, new byte[a.MinNonceSize], ReadOnlySpan<byte>.Empty, a.MinMacSize);

                Assert.NotNull(b);
                Assert.Equal(a.MinMacSize, b.Length);
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithCountMaxSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var b = a.Sign(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, a.MaxMacSize);

                Assert.NotNull(b);
                Assert.Equal(a.MaxMacSize, b.Length);
            }
        }

        #endregion

        #region Sign #3

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Sign(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Sign(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanWithNonceTooShort(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinNonceSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.Throws<ArgumentException>("nonce", () => a.Sign(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanWithNonceTooLong(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Sign(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
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
                    Assert.Throws<ArgumentException>("mac", () => a.Sign(k, new byte[a.MinNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize - 1]));
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
                Assert.Throws<ArgumentException>("mac", () => a.Sign(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanMinSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                a.Sign(k, new byte[a.MinNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize]);
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void SignWithSpanMaxSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                a.Sign(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize]);
            }
        }

        #endregion

        #region TryVerify

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.TryVerify(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.TryVerify(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithNonceTooShort(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinNonceSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.Throws<ArgumentException>("nonce", () => a.TryVerify(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void TryVerifyWithNonceTooLong(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.TryVerify(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
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
                    Assert.False(a.TryVerify(k, new byte[a.MinNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize - 1]));
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
                Assert.False(a.TryVerify(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize + 1]));
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
                var n = new byte[a.MinNonceSize];

                var mac = a.Sign(k, n, d, a.MinMacSize);

                Assert.True(a.TryVerify(k, n, d, mac));
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
                var n = new byte[a.MaxNonceSize];

                var mac = a.Sign(k, n, d, a.MaxMacSize);

                Assert.True(a.TryVerify(k, n, d, mac));
            }
        }

        #endregion

        #region Verify

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithNullKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Verify(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithWrongKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Verify(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithNonceTooShort(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            if (a.MinNonceSize > 0)
            {
                using (var k = new Key(a))
                {
                    Assert.Throws<ArgumentException>("nonce", () => a.Verify(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
                }
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void VerifyWithNonceTooLong(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Verify(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
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
                    Assert.Throws<ArgumentException>("mac", () => a.Verify(k, new byte[a.MinNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.MinMacSize - 1]));
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
                Assert.Throws<ArgumentException>("mac", () => a.Verify(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.MaxMacSize + 1]));
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
                var n = new byte[a.MinNonceSize];

                var mac = a.Sign(k, n, d, a.MinMacSize);

                a.Verify(k, n, d, mac);
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
                var n = new byte[a.MaxNonceSize];

                var mac = a.Sign(k, n, d, a.MaxMacSize);

                a.Verify(k, n, d, mac);
            }
        }

        #endregion
    }
}
