using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class IncrementalSignatureVerificationTests
    {
        public static readonly TheoryData<SignatureAlgorithm2> IncrementalSignatureAlgorithms = Registry.IncrementalSignatureAlgorithms;

        #region Initialize

        [Fact]
        public static void InitializeWithNullAlgorithm()
        {
            using var k = new Key(SignatureAlgorithm.Ed25519ph);

            Assert.Throws<ArgumentNullException>("algorithm", () => IncrementalSignatureVerification.Initialize(null!, k.PublicKey, out _));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void InitializeWithNullKey(SignatureAlgorithm2 a)
        {
            Assert.Throws<ArgumentNullException>("publicKey", () => IncrementalSignatureVerification.Initialize(a, null!, out _));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void InitializeWithWrongKey(SignatureAlgorithm2 a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("publicKey", () => IncrementalSignatureVerification.Initialize(a, k.PublicKey, out var state));
        }

        #endregion

        #region FinalizeAndVerify

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeAndVerifyInvalid(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);
            var state = default(IncrementalSignatureVerification);

            Assert.Throws<InvalidOperationException>(() => IncrementalSignatureVerification.FinalizeAndVerify(ref state, new byte[a.SignatureSize]));
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeAndVerifyFail(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);

            IncrementalSignatureVerification.Initialize(a, k.PublicKey, out var state);

            Assert.False(IncrementalSignatureVerification.FinalizeAndVerify(ref state, new byte[a.SignatureSize]));

            Assert.Null(state.Algorithm);
        }

        [Theory]
        [MemberData(nameof(IncrementalSignatureAlgorithms))]
        public static void FinalizeAndVerifySuccess(SignatureAlgorithm2 a)
        {
            using var k = new Key(a);

            IncrementalSignatureVerification.Initialize(a, k.PublicKey, out var state);

            Assert.True(IncrementalSignatureVerification.FinalizeAndVerify(ref state, a.Sign(k, ReadOnlySpan<byte>.Empty)));

            Assert.Null(state.Algorithm);
        }

        #endregion
    }
}
