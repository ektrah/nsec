using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class IncrementalSignatureTests
    {
        public static readonly TheoryData<SignatureAlgorithm2> IncrementalSignatureAlgorithms = Registry.IncrementalSignatureAlgorithms;

        #region Initialize

        [Fact]
        public static void InitializeWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => IncrementalSignature.Initialize(null!, out _));
        }

        #endregion

        #region Finalize #1

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeInvalid(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.Finalize(ref state, k));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithNullKey(SignatureAlgorithm2 a)
        {
            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentNullException>("key", () => IncrementalSignature.Finalize(ref state, null!));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithWrongKey(SignatureAlgorithm2 a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("key", () => IncrementalSignature.Finalize(ref state, k));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeSuccess(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(0, 100));
            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(100, 100));
            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(200, 100));

            var actual = IncrementalSignature.Finalize(ref state, k);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(k, Utilities.RandomBytes.Slice(0, 300));

            Assert.Equal(expected, actual);
        }

        #endregion

        #region Finalize #2

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanInvalid(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.Finalize(ref state, k, new byte[a.SignatureSize]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanAndNullKey(SignatureAlgorithm2 a)
        {
            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentNullException>("key", () => IncrementalSignature.Finalize(ref state, null!, new byte[a.SignatureSize]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanAndWrongKey(SignatureAlgorithm2 a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("key", () => IncrementalSignature.Finalize(ref state, k, new byte[a.SignatureSize]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanTooSmall(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);

            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("signature", () => IncrementalSignature.Finalize(ref state, k, new byte[a.SignatureSize - 1]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanTooLarge(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);

            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("signature", () => IncrementalSignature.Finalize(ref state, k, new byte[a.SignatureSize + 1]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanSuccess(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(0, 100));
            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(100, 100));
            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(200, 100));

            var actual = new byte[a.SignatureSize];

            IncrementalSignature.Finalize(ref state, k, actual);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(k, Utilities.RandomBytes.Slice(0, 300));

            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanSuccessNoUpdate(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            var actual = new byte[a.SignatureSize];

            IncrementalSignature.Finalize(ref state, k, actual);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(k, ReadOnlySpan<byte>.Empty);

            Assert.Equal(expected, actual);
        }

        #endregion

        #region FinalizeAndVerify

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeAndVerifyInvalid(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.FinalizeAndVerify(ref state, k.PublicKey, new byte[a.SignatureSize]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeAndVerifyWithNullKey(SignatureAlgorithm2 a)
        {
            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentNullException>("publicKey", () => IncrementalSignature.FinalizeAndVerify(ref state, null!, new byte[a.SignatureSize]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeAndVerifyWithWrongKey(SignatureAlgorithm2 a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("publicKey", () => IncrementalSignature.FinalizeAndVerify(ref state, k.PublicKey, new byte[a.SignatureSize]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeAndVerifyFail(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);

            IncrementalSignature.Initialize(a, out var state);

            Assert.False(IncrementalSignature.FinalizeAndVerify(ref state, k.PublicKey, new byte[a.SignatureSize]));

            Assert.Null(state.Algorithm);
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeAndVerifySuccess(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);

            IncrementalSignature.Initialize(a, out var state);

            Assert.True(IncrementalSignature.FinalizeAndVerify(ref state, k.PublicKey, a.Sign(k, ReadOnlySpan<byte>.Empty)));

            Assert.Null(state.Algorithm);
        }

        #endregion
    }
}
