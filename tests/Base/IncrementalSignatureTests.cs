using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class IncrementalSignatureTests
    {
        public static readonly TheoryData<SignatureAlgorithm> IncrementalSignatureAlgorithms = Registry.IncrementalSignatureAlgorithms;

        #region Initialize

        [Fact]
        public static void InitializeWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>("algorithm", () => IncrementalSignature.Initialize(null!, out _));
        }

        [Fact]
        public static void InitializeWithUnsupportedAlgorithm()
        {
            Assert.Throws<NotSupportedException>(() => IncrementalSignature.Initialize(SignatureAlgorithm.Ed25519, out _));
        }

        #endregion

        #region FinalSignature #1

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalSignatureInvalid(SignatureAlgorithm a)
        {
            var state = default(IncrementalSignature);

            var key = new Key(a);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.FinalSignature(ref state, key));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalSignatureSuccess(SignatureAlgorithm a)
        {
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(0, 100));
            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(100, 100));
            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(200, 100));

            var key = new Key(a);
            var actual = IncrementalSignature.FinalSignature(ref state, key);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(key, Utilities.RandomBytes.Slice(0, 300));

            Assert.Equal(expected, actual);
        }

        #endregion

        #region FinalSignature #2

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalSignatureWithSpanInvalid(SignatureAlgorithm a)
        {
            var state = default(IncrementalSignature);

            var key = new Key(a);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.FinalSignature(ref state, key, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalSignatureWithSpanTooSmall(SignatureAlgorithm a)
        {
            var key = new Key(a);

            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("signature", () => IncrementalSignature.FinalSignature(ref state, key, new byte[a.SignatureSize - 1]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanTooLarge(SignatureAlgorithm a)
        {
            var key = new Key(a);

            IncrementalSignature.Initialize(a, out var state);

            Assert.Throws<ArgumentException>("signature", () => IncrementalSignature.FinalSignature(ref state, key, new byte[a.SignatureSize + 1]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalSignatureWithSpanSuccess(SignatureAlgorithm a)
        {
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(0, 100));
            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(100, 100));
            IncrementalSignature.Update(ref state, Utilities.RandomBytes.Slice(200, 100));

            var key = new Key(a);

            var actual = new byte[a.SignatureSize];
            IncrementalSignature.FinalSignature(ref state, key, actual);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(key, Utilities.RandomBytes.Slice(0, 300));

            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalSignatureWithSpanSuccessNoUpdate(SignatureAlgorithm a)
        {
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(a, out state);

            Assert.Same(a, state.Algorithm);

            var key = new Key(a);

            var actual = new byte[a.SignatureSize];
            IncrementalSignature.FinalSignature(ref state, key, actual);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(key, ReadOnlySpan<byte>.Empty);

            Assert.Equal(expected, actual);
        }

        #endregion

        #region FinalVerify

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalVerifyInvalid(SignatureAlgorithm a)
        {
            var state = default(IncrementalSignature);

            var key = new Key(a);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.FinalVerify(ref state, key.PublicKey, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalVerifyNullKey(SignatureAlgorithm a)
        {
            var state = default(IncrementalSignature);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.FinalVerify(ref state, null!, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalVerifyKeyFromdifferentAlgorithm(SignatureAlgorithm a)
        {
            var state = default(IncrementalSignature);

            var key = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.FinalVerify(ref state, key.PublicKey, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalVerifySuccess(SignatureAlgorithm a)
        {
            IncrementalSignature.Initialize(a, out var state);

            var key = new Key(a);
            var signature = a.Sign(key, ReadOnlySpan<byte>.Empty);

            Assert.True(IncrementalSignature.FinalVerify(ref state, key.PublicKey, signature));

            Assert.Null(state.Algorithm);
        }

        #endregion
    }
}
