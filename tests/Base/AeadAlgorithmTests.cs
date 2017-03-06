using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class AeadAlgorithmTests
    {
        public static readonly TheoryData<Type> AeadAlgorithms = Registry.AeadAlgorithms;

        private const int L = 547;

        #region Properties

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.KeySize > 0);
            Assert.True(a.NonceSize > 0);
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
                Assert.Throws<ArgumentException>("nonce", () => a.Encrypt(k, new byte[a.NonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Encrypt(k, new byte[a.NonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptEmptySuccess(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var b = a.Encrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);

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
                Assert.Throws<ArgumentException>("nonce", () => a.Encrypt(k, new byte[a.NonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithSpanWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Encrypt(k, new byte[a.NonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptEmptyWithSpanTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("ciphertext", () => a.Encrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptEmptyWithSpanTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("ciphertext", () => a.Encrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, new byte[a.TagSize + 1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithSpanOutOfPlace(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var n = Utilities.RandomBytes.Slice(0, a.NonceSize);
                var ad = Utilities.RandomBytes.Slice(0, 100);

                var expected = new byte[L + a.TagSize];
                var actual = new byte[L + a.TagSize];

                var plaintext = Utilities.RandomBytes.Slice(0, L);

                a.Encrypt(k, n, ad, plaintext, expected);
                a.Encrypt(k, n, ad, plaintext, actual);
                Assert.Equal(expected, actual);
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void EncryptWithSpanInPlace(Type algorithmType)
        {

            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var n = Utilities.RandomBytes.Slice(0, a.NonceSize);
                var ad = Utilities.RandomBytes.Slice(0, 100);

                var actual = new byte[L + a.TagSize];
                var expected = new byte[L + a.TagSize];
                Utilities.RandomBytes.Slice(0, L).CopyTo(actual);

                a.Encrypt(k, n, ad, new ReadOnlySpan<byte>(actual, 0, L), expected);
                a.Encrypt(k, n, ad, new ReadOnlySpan<byte>(actual, 0, L), actual);
                Assert.Equal(expected, actual);
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
                Assert.Throws<ArgumentException>("nonce", () => a.Decrypt(k, new byte[a.NonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Decrypt(k, new byte[a.NonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithCiphertextTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<CryptographicException>(() => a.Decrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptEmptySuccess(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                var pt = a.Decrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ct);
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
                Assert.Throws<ArgumentException>("nonce", () => a.Decrypt(k, new byte[a.NonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.Decrypt(k, new byte[a.NonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanWithCiphertextTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<CryptographicException>(() => a.Decrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1], Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                Assert.Throws<ArgumentException>("plaintext", () => a.Decrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ct, new byte[1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanOutOfPlace(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var n = Utilities.RandomBytes.Slice(0, a.NonceSize);
                var ad = Utilities.RandomBytes.Slice(0, 100);

                var expected = Utilities.RandomBytes.Slice(0, L).ToArray();
                var actual = new byte[L];

                var ciphertext = a.Encrypt(k, n, ad, expected);

                a.Decrypt(k, n, ad, ciphertext, actual);
                Assert.Equal(expected, actual);
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void DecryptWithSpanInPlace(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var n = Utilities.RandomBytes.Slice(0, a.NonceSize);
                var ad = Utilities.RandomBytes.Slice(0, 100);

                var actual = new byte[L + a.TagSize];
                var expected = new byte[L + a.TagSize];

                a.Encrypt(k, n, ad, Utilities.RandomBytes.Slice(0, L), actual);
                a.Encrypt(k, n, ad, Utilities.RandomBytes.Slice(0, L), expected);

                a.Decrypt(k, n, ad, actual, new Span<byte>(expected, 0, L));
                a.Decrypt(k, n, ad, actual, new Span<byte>(actual, 0, L));
                Assert.Equal(expected, actual);
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
                Assert.Throws<ArgumentException>("nonce", () => a.TryDecrypt(k, new byte[a.NonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, out byte[] pt));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.TryDecrypt(k, new byte[a.NonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, out byte[] pt));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithCiphertextTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.False(a.TryDecrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1], out byte[] pt));
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

                var ct = new byte[pt.Length + a.TagSize];

                Assert.False(a.TryDecrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ct, pt));
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
                var ct = a.Encrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                Assert.True(a.TryDecrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ct, out byte[] pt));
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
                Assert.Throws<ArgumentException>("nonce", () => a.TryDecrypt(k, new byte[a.NonceSize - 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanWithNonceTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.Throws<ArgumentException>("nonce", () => a.TryDecrypt(k, new byte[a.NonceSize + 1], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanWithCiphertextTooSmall(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                Assert.False(a.TryDecrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, new byte[a.TagSize - 1], Span<byte>.Empty));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanTooLarge(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var ct = a.Encrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
                Assert.NotNull(ct);
                Assert.Equal(a.TagSize, ct.Length);

                Assert.Throws<ArgumentException>("plaintext", () => a.TryDecrypt(k, new byte[a.NonceSize], ReadOnlySpan<byte>.Empty, ct, new byte[1]));
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanOutOfPlace(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var n = Utilities.RandomBytes.Slice(0, a.NonceSize);
                var ad = Utilities.RandomBytes.Slice(0, 100);

                var expected = Utilities.RandomBytes.Slice(0, L).ToArray();
                var actual = new byte[L];

                var ciphertext = a.Encrypt(k, n, ad, expected);

                Assert.True(a.TryDecrypt(k, n, ad, ciphertext, actual));
                Assert.Equal(expected, actual);
            }
        }

        [Theory]
        [MemberData(nameof(AeadAlgorithms))]
        public static void TryDecryptWithSpanInPlace(Type algorithmType)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            using (var k = new Key(a))
            {
                var n = Utilities.RandomBytes.Slice(0, a.NonceSize);
                var ad = Utilities.RandomBytes.Slice(0, 100);

                var actual = new byte[L + a.TagSize];
                var expected = new byte[L + a.TagSize];

                a.Encrypt(k, n, ad, Utilities.RandomBytes.Slice(0, L), actual);
                a.Encrypt(k, n, ad, Utilities.RandomBytes.Slice(0, L), expected);

                Assert.True(a.TryDecrypt(k, n, ad, actual, new Span<byte>(expected, 0, L)));
                Assert.True(a.TryDecrypt(k, n, ad, actual, new Span<byte>(actual, 0, L)));
                Assert.Equal(expected, actual);
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

                var unexpected = new byte[actual.Length];
                Utilities.Fill(unexpected, 0xDB);

                Assert.NotEqual(unexpected, actual);
            }
        }

        #endregion
    }
}
