using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class AeadAlgorithmTests
    {
        public static readonly TheoryData<Type> AeadAlgorithms = Registry.AeadAlgorithms;

        #region Properties

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.KeySize >= 32);
            Assert.True(a.MinNonceSize > 0);
            Assert.True(a.MaxNonceSize >= a.MinNonceSize);
            Assert.True(a.TagSize > 0);
        }

        #endregion

        #region Encrypt #1

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithNullKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Encrypt(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithWrongKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Encrypt(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithNonceTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Encrypt(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Encrypt(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptEmptySuccess(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var b = a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);

                Assert.NotNull(b);
                Assert.Equal(a.TagSize, b.Length);
            }
        }

        #endregion

        #region Encrypt #2

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithSpanWithNullKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Encrypt(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithSpanWithWrongKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Encrypt(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithSpanWithNonceTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Encrypt(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithSpanWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Encrypt(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptEmptyWithSpanTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("ciphertext", () => a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptEmptyWithSpanTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("ciphertext", () => a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[a.TagSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptEmptyWithSpanSuccess(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[a.TagSize]);
            }
        }

        #endregion

        #region Decrypt #1

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithNullKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Decrypt(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithWrongKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Decrypt(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithNonceTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Decrypt(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Decrypt(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithCiphertextTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<CryptographicException>(() => a.Decrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptEmptySuccess(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                var pt = a.Decrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ct);
                Assert.NotNull(pt);
                Assert.Equal(0, pt.Length);
            }
        }

        #endregion

        #region Decrypt #2

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanWithNullKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.Decrypt(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanWithWrongKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.Decrypt(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanWithNonceTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Decrypt(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Decrypt(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanWithCiphertextTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<CryptographicException>(() => a.Decrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1], Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                Assert.Throws<ArgumentException>("plaintext", () => a.Decrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ct, new byte[1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanEmptySuccess(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                a.Decrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ct, Span<byte>.Empty);
            }
        }

        #endregion

        #region TryDecrypt #1

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithNullKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.TryDecrypt(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, out byte[] pt));
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithWrongKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.TryDecrypt(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, out byte[] pt));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithNonceTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.TryDecrypt(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, out byte[] pt));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.TryDecrypt(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, out byte[] pt));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithCiphertextTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.False(a.TryDecrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1], out byte[] pt));
                Assert.Null(pt);
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptFailClearsPlaintext(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var pt = new byte[16];
                for (var i = 0; i < pt.Length; i++)
                {
                    pt[i] = 0xD6;
                }

                var ct = new byte[32];

                Assert.False(a.TryDecrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ct, pt));
                Assert.Equal(new byte[pt.Length], pt);
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptEmptySuccess(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                Assert.True(a.TryDecrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ct, out byte[] pt));
                Assert.NotNull(pt);
                Assert.Equal(0, pt.Length);
            }
        }

        #endregion

        #region TryDecrypt #2

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanWithNullKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("key", () => a.TryDecrypt(null, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanWithWrongKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(new Ed25519()))
            {
                Assert.Throws<ArgumentException>("key", () => a.TryDecrypt(k, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanWithNonceTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.TryDecrypt(k, new byte[a.MinNonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.TryDecrypt(k, new byte[a.MaxNonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanWithCiphertextTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.False(a.TryDecrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1], Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                Assert.Throws<ArgumentException>("plaintext", () => a.TryDecrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ct, new byte[1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanEmptySuccess(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                Assert.True(a.TryDecrypt(k, new byte[a.MaxNonceSize], ReadOnlySpan<byte>.Empty, ct, Span<byte>.Empty));
            }
        }

        #endregion

        #region CreateKey

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void CreateKey(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a, KeyFlags.AllowArchiving))
            {
                var actual = k.Export(KeyBlobFormat.RawSymmetricKey);

                var expected = new byte[actual.Length];
                Utilities.Fill(expected, 0xD0);

                Assert.NotEqual(expected, actual);
            }
        }

        #endregion
    }
}
