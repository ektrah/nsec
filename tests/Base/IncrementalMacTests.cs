using System;
using NSec.Cryptography;
using NSec.Experimental;
using Xunit;

namespace NSec.Tests.Base
{
    public static class IncrementalMacTests
    {
        public static readonly TheoryData<Type> MacAlgorithms = Registry.MacAlgorithms;

        #region Initialize

        [Fact]
        public static void InitializeWithNullKey()
        {
            Assert.Throws<ArgumentNullException>("key", () => IncrementalMac.Initialize(null, out _));
        }

        [Fact]
        public static void InitializeWithWrongKey()
        {
            var a = AeadAlgorithm.ChaCha20Poly1305;

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("key", () => IncrementalMac.Initialize(k, out _));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void InitializeWithDisposedKey(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            var k = new Key(a);
            k.Dispose();
            Assert.Throws<ObjectDisposedException>(() => IncrementalMac.Initialize(k, out _));
        }

        #endregion

        #region Update

        [Fact]
        public static void UpdateInvalid()
        {
            var state = default(IncrementalMac);

            Assert.Throws<InvalidOperationException>(() => IncrementalMac.Update(ref state, Utilities.RandomBytes.Slice(0, 100)));
        }

        #endregion

        #region Finalize #1

        [Fact]
        public static void FinalizeInvalid()
        {
            var state = default(IncrementalMac);

            Assert.Throws<InvalidOperationException>(() => IncrementalMac.Finalize(ref state));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var state = default(IncrementalMac);

                Assert.Null(state.Algorithm);

                IncrementalMac.Initialize(k, out state);

                Assert.Same(a, state.Algorithm);

                IncrementalMac.Update(ref state, Utilities.RandomBytes.Slice(0, 100));
                IncrementalMac.Update(ref state, Utilities.RandomBytes.Slice(100, 100));
                IncrementalMac.Update(ref state, Utilities.RandomBytes.Slice(200, 100));

                var actual = IncrementalMac.Finalize(ref state);

                Assert.Null(state.Algorithm);

                var expected = a.Mac(k, Utilities.RandomBytes.Slice(0, 300));

                Assert.Equal(expected, actual);
            }
        }

        #endregion

        #region Finalize #2

        [Fact]
        public static void FinalizeWithSpanInvalid()
        {
            var state = default(IncrementalMac);

            Assert.Throws<InvalidOperationException>(() => IncrementalMac.Finalize(ref state, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeWithSpanTooSmall(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                IncrementalMac.Initialize(k, out var state);

                Assert.Throws<ArgumentException>("mac", () => IncrementalMac.Finalize(ref state, new byte[a.MacSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeWithSpanTooLarge(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                IncrementalMac.Initialize(k, out var state);

                Assert.Throws<ArgumentException>("mac", () => IncrementalMac.Finalize(ref state, new byte[a.MacSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeWithSpanSuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var state = default(IncrementalMac);

                Assert.Null(state.Algorithm);

                IncrementalMac.Initialize(k, out state);

                Assert.Same(a, state.Algorithm);

                IncrementalMac.Update(ref state, Utilities.RandomBytes.Slice(0, 100));
                IncrementalMac.Update(ref state, Utilities.RandomBytes.Slice(100, 100));
                IncrementalMac.Update(ref state, Utilities.RandomBytes.Slice(200, 100));

                var actual = new byte[a.MacSize];

                IncrementalMac.Finalize(ref state, actual);

                Assert.Null(state.Algorithm);

                var expected = a.Mac(k, Utilities.RandomBytes.Slice(0, 300));

                Assert.Equal(expected, actual);
            }
        }

        #endregion

        #region FinalizeAndVerify

        [Fact]
        public static void FinalizeAndVerifyInvalid()
        {
            var state = default(IncrementalMac);

            Assert.Throws<InvalidOperationException>(() => IncrementalMac.FinalizeAndVerify(ref state, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeAndVerifyFail(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                IncrementalMac.Initialize(k, out var state);

                Assert.False(IncrementalMac.FinalizeAndVerify(ref state, new byte[a.MacSize]));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeAndVerifySuccess(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                IncrementalMac.Initialize(k, out var state);

                Assert.True(IncrementalMac.FinalizeAndVerify(ref state, a.Mac(k, ReadOnlySpan<byte>.Empty)));
            }
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeWithSpanSuccessNoUpdate(Type algorithmType)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var state = default(IncrementalMac);

                Assert.Null(state.Algorithm);

                IncrementalMac.Initialize(k, out state);

                Assert.Same(a, state.Algorithm);

                var actual = new byte[a.MacSize];

                IncrementalMac.Finalize(ref state, actual);

                Assert.Null(state.Algorithm);

                var expected = a.Mac(k, ReadOnlySpan<byte>.Empty);

                Assert.Equal(expected, actual);
            }
        }

        #endregion
    }
}
