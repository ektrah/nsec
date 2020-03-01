using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class IncrementalMacTests
    {
        public static readonly TheoryData<MacAlgorithm> MacAlgorithms = Registry.MacAlgorithms;

        #region Initialize

        [Fact]
        public static void InitializeWithNullKey()
        {
            Assert.Throws<ArgumentNullException>("key", () => IncrementalMac.Initialize(null!, out _));
        }

        [Fact]
        public static void InitializeWithWrongKey()
        {
            var a = AeadAlgorithm.ChaCha20Poly1305;

            using var k = new Key(a);

            Assert.Throws<ArgumentException>("key", () => IncrementalMac.Initialize(k, out _));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void InitializeWithDisposedKey(MacAlgorithm a)
        {
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
        public static void FinalizeSuccess(MacAlgorithm a)
        {
            using var k = new Key(a);
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
        public static void FinalizeWithSpanTooSmall(MacAlgorithm a)
        {
            using var k = new Key(a);

            IncrementalMac.Initialize(k, out var state);

            Assert.Throws<ArgumentException>("mac", () => IncrementalMac.Finalize(ref state, new byte[a.MacSize - 1]));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeWithSpanTooLarge(MacAlgorithm a)
        {
            using var k = new Key(a);

            IncrementalMac.Initialize(k, out var state);

            Assert.Throws<ArgumentException>("mac", () => IncrementalMac.Finalize(ref state, new byte[a.MacSize + 1]));
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeWithSpanSuccess(MacAlgorithm a)
        {
            using var k = new Key(a);
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
        public static void FinalizeAndVerifyFail(MacAlgorithm a)
        {
            using var k = new Key(a);

            IncrementalMac.Initialize(k, out var state);

            Assert.False(IncrementalMac.FinalizeAndVerify(ref state, new byte[a.MacSize]));

            Assert.Null(state.Algorithm);
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeAndVerifySuccess(MacAlgorithm a)
        {
            using var k = new Key(a);

            IncrementalMac.Initialize(k, out var state);

            Assert.True(IncrementalMac.FinalizeAndVerify(ref state, a.Mac(k, ReadOnlySpan<byte>.Empty)));

            Assert.Null(state.Algorithm);
        }

        [Theory]
        [MemberData(nameof(MacAlgorithms))]
        public static void FinalizeWithSpanSuccessNoUpdate(MacAlgorithm a)
        {
            using var k = new Key(a);
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

        #endregion
    }
}
