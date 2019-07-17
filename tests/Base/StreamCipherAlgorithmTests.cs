
using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class StreamCipherAlgorithmTests
    {
        public static readonly TheoryData<StreamCipherAlgorithm> StreamCipherAlgorithms = Registry.StreamCipherAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void Properties(StreamCipherAlgorithm a)
        {
            Assert.True(a.KeySize > 0);
            Assert.InRange(a.NonceSize, 0, Nonce.MaxSize);
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithNullKey(StreamCipherAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("key", () => a.GeneratePseudoRandomStream(null, default(Nonce), 1));
            Assert.Throws<ArgumentNullException>("key", () => a.XOr(null, default(Nonce), ReadOnlySpan<byte>.Empty));
            Assert.Throws<ArgumentNullException>("key", () => a.XOrIC(null, default(Nonce), ReadOnlySpan<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void EncryptWithDisposedKey(StreamCipherAlgorithm a)
        {
            var k = new Key(a);
            k.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.GeneratePseudoRandomStream(k, new Nonce(0, a.NonceSize), 1));
            Assert.Throws<ObjectDisposedException>(() => a.XOr(k, new Nonce(0, a.NonceSize), ReadOnlySpan<byte>.Empty));
            Assert.Throws<ObjectDisposedException>(() => a.XOrIC(k,new Nonce(0, a.NonceSize), ReadOnlySpan<byte>.Empty, 1));
        }

        #endregion
    }
}
