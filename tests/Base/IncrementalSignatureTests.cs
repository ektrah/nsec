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
        public static void InitializeWithNullKey()
        {
            Assert.Throws<ArgumentNullException>("privateKey", () => IncrementalSignature.Initialize(null!, out _));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void InitializeWithWrongKey(SignatureAlgorithm2 a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("privateKey", () => IncrementalSignature.Initialize(k, out var state));
        }

        #endregion

        #region Finalize #1

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeInvalid(SignatureAlgorithm2 a)
        {
            var state = default(IncrementalSignature);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.Finalize(ref state));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeSuccess(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(k, out state);

            Assert.Same(a, state.Algorithm);

            IncrementalSignature.Update(ref state, Utilities.RandomBytes[..100]);
            IncrementalSignature.Update(ref state, Utilities.RandomBytes[100..200]);
            IncrementalSignature.Update(ref state, Utilities.RandomBytes[200..300]);

            var actual = IncrementalSignature.Finalize(ref state);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(k, Utilities.RandomBytes[..300]);

            Assert.Equal(expected, actual);
        }

        #endregion

        #region Finalize #2

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanInvalid(SignatureAlgorithm2 a)
        {
            var state = default(IncrementalSignature);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignature.Finalize(ref state, new byte[a.SignatureSize]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanTooSmall(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);

            IncrementalSignature.Initialize(k, out var state);

            Assert.Throws<ArgumentException>("signature", () => IncrementalSignature.Finalize(ref state, new byte[a.SignatureSize - 1]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanTooLarge(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);

            IncrementalSignature.Initialize(k, out var state);

            Assert.Throws<ArgumentException>("signature", () => IncrementalSignature.Finalize(ref state, new byte[a.SignatureSize + 1]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanSuccess(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(k, out state);

            Assert.Same(a, state.Algorithm);

            IncrementalSignature.Update(ref state, Utilities.RandomBytes[..100]);
            IncrementalSignature.Update(ref state, Utilities.RandomBytes[100..200]);
            IncrementalSignature.Update(ref state, Utilities.RandomBytes[200..300]);

            var actual = new byte[a.SignatureSize];

            IncrementalSignature.Finalize(ref state, actual);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(k, Utilities.RandomBytes[..300]);

            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeWithSpanSuccessNoUpdate(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignature);

            Assert.Null(state.Algorithm);

            IncrementalSignature.Initialize(k, out state);

            Assert.Same(a, state.Algorithm);

            var actual = new byte[a.SignatureSize];

            IncrementalSignature.Finalize(ref state, actual);

            Assert.Null(state.Algorithm);

            var expected = a.Sign(k, []);

            Assert.Equal(expected, actual);
        }

        #endregion
    }
}
