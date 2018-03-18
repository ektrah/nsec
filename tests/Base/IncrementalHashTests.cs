using System;
using NSec.Cryptography;
using NSec.Experimental;
using Xunit;

namespace NSec.Tests.Base
{
    public static class IncrementalHashTests
    {
        public static readonly TheoryData<Type> HashAlgorithms = Registry.HashAlgorithms;

        #region Initialize

        [Fact]
        public static void InitializeWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => IncrementalHash.Initialize(null, out _));
        }

        #endregion

        #region Update

        [Fact]
        public static void UpdateInvalid()
        {
            var state = default(IncrementalHash);

            Assert.Throws<InvalidOperationException>(() => IncrementalHash.Update(ref state, Utilities.RandomBytes.Slice(0, 100)));
        }

        #endregion

        #region Finalize #1

        [Fact]
        public static void FinalizeInvalid()
        {
            var state = default(IncrementalHash);

            Assert.Throws<InvalidOperationException>(() => IncrementalHash.Finalize(ref state));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var state = default(IncrementalHash);

            Assert.Null(state.Algorithm);

            IncrementalHash.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            IncrementalHash.Update(ref state, Utilities.RandomBytes.Slice(0, 100));
            IncrementalHash.Update(ref state, Utilities.RandomBytes.Slice(100, 100));
            IncrementalHash.Update(ref state, Utilities.RandomBytes.Slice(200, 100));

            var actual = IncrementalHash.Finalize(ref state);

            Assert.Null(state.Algorithm);

            var expected = a.Hash(Utilities.RandomBytes.Slice(0, 300));

            Assert.Equal(expected, actual);
        }

        #endregion

        #region Finalize #2

        [Fact]
        public static void FinalizeWithSpanInvalid()
        {
            var state = default(IncrementalHash);

            Assert.Throws<InvalidOperationException>(() => IncrementalHash.Finalize(ref state, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeWithSpanTooSmall(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            IncrementalHash.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("hash", () => IncrementalHash.Finalize(ref state, new byte[a.HashSize - 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeWithSpanTooLarge(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            IncrementalHash.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("hash", () => IncrementalHash.Finalize(ref state, new byte[a.HashSize + 1]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeWithSpanSuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var state = default(IncrementalHash);

            Assert.Null(state.Algorithm);

            IncrementalHash.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            IncrementalHash.Update(ref state, Utilities.RandomBytes.Slice(0, 100));
            IncrementalHash.Update(ref state, Utilities.RandomBytes.Slice(100, 100));
            IncrementalHash.Update(ref state, Utilities.RandomBytes.Slice(200, 100));

            var actual = new byte[a.HashSize];

            IncrementalHash.Finalize(ref state, actual);

            Assert.Null(state.Algorithm);

            var expected = a.Hash(Utilities.RandomBytes.Slice(0, 300));

            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeWithSpanSuccessNoUpdate(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            var state = default(IncrementalHash);

            Assert.Null(state.Algorithm);

            IncrementalHash.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            var actual = new byte[a.HashSize];

            IncrementalHash.Finalize(ref state, actual);

            Assert.Null(state.Algorithm);

            var expected = a.Hash(ReadOnlySpan<byte>.Empty);

            Assert.Equal(expected, actual);
        }

        #endregion

        #region FinalizeAndTryVerify

        [Fact]
        public static void FinalizeAndTryVerifyInvalid()
        {
            var state = default(IncrementalHash);

            Assert.Throws<InvalidOperationException>(() => IncrementalHash.FinalizeAndTryVerify(ref state, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeAndTryVerifyFail(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            IncrementalHash.Initialize(a, out var state);

            Assert.False(IncrementalHash.FinalizeAndTryVerify(ref state, new byte[a.HashSize]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeAndTryVerifySuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            IncrementalHash.Initialize(a, out var state);

            Assert.True(IncrementalHash.FinalizeAndTryVerify(ref state, a.Hash(ReadOnlySpan<byte>.Empty)));
        }

        #endregion

        #region FinalizeAndVerify

        [Fact]
        public static void FinalizeAndVerifyInvalid()
        {
            var state = default(IncrementalHash);

            Assert.Throws<InvalidOperationException>(() => IncrementalHash.FinalizeAndVerify(ref state, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeAndVerifyFail(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            IncrementalHash.Initialize(a, out var state);

            Assert.Throws<CryptographicException>(() => IncrementalHash.FinalizeAndVerify(ref state, new byte[a.HashSize]));
        }

        [Theory]
        [MemberData(nameof(HashAlgorithms))]
        public static void FinalizeAndVerifySuccess(Type algorithmType)
        {
            var a = (HashAlgorithm)Activator.CreateInstance(algorithmType);

            IncrementalHash.Initialize(a, out var state);

            IncrementalHash.FinalizeAndVerify(ref state, a.Hash(ReadOnlySpan<byte>.Empty));
        }

        #endregion
    }
}
