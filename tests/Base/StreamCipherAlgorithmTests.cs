using System;
using NSec.Cryptography;
using NSec.Experimental;
using Xunit;

namespace NSec.Tests.Base
{
    public static class StreamCipherAlgorithmTests
    {
        public static readonly TheoryData<StreamCipherAlgorithm> StreamCipherAlgorithms = Registry.StreamCipherAlgorithms;

        private const int L = 547;

        #region Properties

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void Properties(StreamCipherAlgorithm a)
        {
            Assert.True(a.KeySize > 0);
            Assert.InRange(a.NonceSize, 0, Nonce.MaxSize);
        }

        #endregion

        #region Operation #1

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithNullKey(StreamCipherAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("key", () => a.GeneratePseudoRandomStream(null!, default, 1));
            Assert.Throws<ArgumentNullException>("key", () => a.XOr(null!, default, ReadOnlySpan<byte>.Empty));
            Assert.Throws<ArgumentNullException>("key", () => a.XOrIC(null!, default, ReadOnlySpan<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithDisposedKey(StreamCipherAlgorithm a)
        {
            var k = new Key(a);
            k.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.GeneratePseudoRandomStream(k, new Nonce(0, a.NonceSize), 1));
            Assert.Throws<ObjectDisposedException>(() => a.XOr(k, new Nonce(0, a.NonceSize), ReadOnlySpan<byte>.Empty));
            Assert.Throws<ObjectDisposedException>(() => a.XOrIC(k, new Nonce(0, a.NonceSize), ReadOnlySpan<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithWrongKey(StreamCipherAlgorithm a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("key", () => a.GeneratePseudoRandomStream(k, default, 1));
            Assert.Throws<ArgumentException>("key", () => a.XOr(k, default, ReadOnlySpan<byte>.Empty));
            Assert.Throws<ArgumentException>("key", () => a.XOrIC(k, default, ReadOnlySpan<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithNonceTooSmall(StreamCipherAlgorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("nonce", () => a.GeneratePseudoRandomStream(k, new Nonce(0, a.NonceSize - 1), 1));
            Assert.Throws<ArgumentException>("nonce", () => a.XOr(k, new Nonce(0, a.NonceSize - 1), ReadOnlySpan<byte>.Empty));
            Assert.Throws<ArgumentException>("nonce", () => a.XOrIC(k, new Nonce(0, a.NonceSize - 1), ReadOnlySpan<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithNonceTooLarge(StreamCipherAlgorithm a)
        {
            if (a.NonceSize == Nonce.MaxSize)
            {
                return;
            }

            using var k = new Key(a);

            Assert.Throws<ArgumentException>("nonce", () => a.GeneratePseudoRandomStream(k, new Nonce(0, a.NonceSize + 1), 1));
            Assert.Throws<ArgumentException>("nonce", () => a.XOr(k, new Nonce(0, a.NonceSize + 1), ReadOnlySpan<byte>.Empty));
            Assert.Throws<ArgumentException>("nonce", () => a.XOrIC(k, new Nonce(0, a.NonceSize + 1), ReadOnlySpan<byte>.Empty, 1));
        }

        #endregion

        #region Operation #2

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithSpanWithNullKey(StreamCipherAlgorithm a)
        {
            Assert.Throws<ArgumentNullException>("key", () => a.GeneratePseudoRandomStream(null!, default, Span<byte>.Empty));
            Assert.Throws<ArgumentNullException>("key", () => a.XOr(null!, default, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            Assert.Throws<ArgumentNullException>("key", () => a.XOrIC(null!, default, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithSpanWithDisposedKey(StreamCipherAlgorithm a)
        {
            var k = new Key(a);
            k.Dispose();
            Assert.Throws<ObjectDisposedException>(() => a.GeneratePseudoRandomStream(k, new Nonce(0, a.NonceSize), Span<byte>.Empty));
            Assert.Throws<ObjectDisposedException>(() => a.XOr(k, new Nonce(0, a.NonceSize), ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            Assert.Throws<ObjectDisposedException>(() => a.XOrIC(k, new Nonce(0, a.NonceSize), ReadOnlySpan<byte>.Empty, Span<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithSpanWithWrongKey(StreamCipherAlgorithm a)
        {
            using var k = new Key(SignatureAlgorithm.Ed25519);

            Assert.Throws<ArgumentException>("key", () => a.GeneratePseudoRandomStream(k, default, Span<byte>.Empty));
            Assert.Throws<ArgumentException>("key", () => a.XOr(k, default, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            Assert.Throws<ArgumentException>("key", () => a.XOrIC(k, default, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithSpanWithNonceTooSmall(StreamCipherAlgorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("nonce", () => a.GeneratePseudoRandomStream(k, new Nonce(0, a.NonceSize - 1), Span<byte>.Empty));
            Assert.Throws<ArgumentException>("nonce", () => a.XOr(k, new Nonce(0, a.NonceSize - 1), ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            Assert.Throws<ArgumentException>("nonce", () => a.XOrIC(k, new Nonce(0, a.NonceSize - 1), ReadOnlySpan<byte>.Empty, Span<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithSpanWithNonceTooLarge(StreamCipherAlgorithm a)
        {
            using var k = new Key(a);

            Assert.Throws<ArgumentException>("nonce", () => a.GeneratePseudoRandomStream(k, new Nonce(0, a.NonceSize + 1), Span<byte>.Empty));
            Assert.Throws<ArgumentException>("nonce", () => a.XOr(k, new Nonce(0, a.NonceSize + 1), ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            Assert.Throws<ArgumentException>("nonce", () => a.XOrIC(k, new Nonce(0, a.NonceSize + 1), ReadOnlySpan<byte>.Empty, Span<byte>.Empty, 1));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithNonceOverlapping(StreamCipherAlgorithm a)
        {
            using var k = new Key(a);
            var b = Utilities.RandomBytes.Slice(0, 100);

            var expected = new byte[b.Length];
            var actual = new byte[b.Length];
            Utilities.RandomBytes.Slice(200, actual.Length).CopyTo(actual);

            var n = new Nonce(actual.AsSpan(10, a.NonceSize), 0);
            a.XOr(k, n, b, expected);
            a.XOr(k, n, b, actual);
            Assert.Equal(expected, actual);

            Utilities.RandomBytes.Slice(200, actual.Length).CopyTo(actual);
            var incrCount = BitConverter.ToUInt32(Utilities.RandomBytes.Slice(0, 4));
            a.XOrIC(k, n, b, expected, incrCount);
            a.XOrIC(k, n, b, actual, incrCount);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithPlainTextOverlapping(StreamCipherAlgorithm a)
        {
            using var k = new Key(a);
            var n = new Nonce(Utilities.RandomBytes.Slice(0, a.NonceSize), 0);
            var b = Utilities.RandomBytes.Slice(200, 200).ToArray();

            Assert.Throws<ArgumentException>("output", () => a.XOr(k, n, b.AsSpan(10, 100), b.AsSpan(60, 100)));
            Assert.Throws<ArgumentException>("output", () => a.XOr(k, n, b.AsSpan(60, 100), b.AsSpan(10, 100)));
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithSpanOutOfPlace(StreamCipherAlgorithm a)
        {
            using var k = new Key(a);
            var n = new Nonce(Utilities.RandomBytes.Slice(0, a.NonceSize), 0);

            var expected = new byte[L];
            var actual = new byte[L];

            var plaintext = Utilities.RandomBytes.Slice(0, L);

            a.XOr(k, n, plaintext, expected);
            a.XOr(k, n, plaintext, actual);
            Assert.Equal(expected, actual);

            var incrCount = BitConverter.ToUInt32(Utilities.RandomBytes.Slice(0, 4));
            a.XOrIC(k, n, actual.AsSpan(0, L), expected, incrCount);
            a.XOrIC(k, n, actual.AsSpan(0, L), actual, incrCount);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void OperationWithSpanInPlace(StreamCipherAlgorithm a)
        {
            using var k = new Key(a);
            var n = new Nonce(Utilities.RandomBytes.Slice(0, a.NonceSize), 0);

            var expected = new byte[L];
            var actual = new byte[L];
            Utilities.RandomBytes.Slice(0, L).CopyTo(actual);

            a.XOr(k, n, actual.AsSpan(0, L), expected);
            a.XOr(k, n, actual.AsSpan(0, L), actual);
            Assert.Equal(expected, actual);

            var incrCount = BitConverter.ToUInt32(Utilities.RandomBytes.Slice(0, 4));
            a.XOrIC(k, n, actual.AsSpan(0, L), expected, incrCount);
            a.XOrIC(k, n, actual.AsSpan(0, L), actual, incrCount);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region CreateKey

        [Theory]
        [MemberData(nameof(StreamCipherAlgorithms))]
        public static void CreateKey(StreamCipherAlgorithm a)
        {
            using var k = new Key(a, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
            Assert.Same(a, k.Algorithm);
            Assert.False(k.HasPublicKey);
            Assert.Throws<InvalidOperationException>(() => k.PublicKey);
            Assert.Equal(a.KeySize, k.Size);

            var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

            var unexpected = new byte[actual.Length];
            Utilities.Fill(unexpected, actual[0]);

            Assert.NotEqual(unexpected, actual);
        }

        #endregion
    }
}
