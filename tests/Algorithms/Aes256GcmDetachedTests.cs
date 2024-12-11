using NSec.Cryptography;
using System;
using System.Text.Json;
using Xunit;
using static Interop.Libsodium;

namespace NSec.Tests.Algorithms
{
    public static class Aes256GcmDetachedTests
    {
        public static readonly TheoryData<int> PlaintextLengths = Utilities.Primes;

        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = AeadDetachedAlgorithm.Aes256Gcm;

            Assert.Equal(32, a.KeySize);
            Assert.Equal(12, a.NonceSize);
            Assert.Equal(16, a.TagSize);
        }

        [Fact]
        public static void IsSupported()
        {
            Assert.InRange(Aes256GcmDetached.IsSupported, false, true);
        }

        #endregion

        #region Encrypt/Decrypt

        [Theory]
        [MemberData(nameof(PlaintextLengths))]
        public static void EncryptDecrypt(int length)
        {
            var a = AeadDetachedAlgorithm.Aes256Gcm;

            using var k = new Key(a);
            var n = Utilities.RandomBytes[..a.NonceSize];
            var ad = Utilities.RandomBytes[..100];

            var expected = Utilities.RandomBytes[..length].ToArray();

            Span<byte> ciphertext = new byte[length];
            Span<byte> tag = new byte[a.TagSize];
            Span<byte> actual = new byte[length];

            a.Encrypt(k, n, ad, expected, ciphertext, tag);

            var decryptResult = a.Decrypt(k, n, ad, ciphertext, tag, actual);
            Assert.True(decryptResult);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(PlaintextLengths))]
        public static void EncryptDetachedDecryptCombined(int length)
        {
            var detached = AeadDetachedAlgorithm.Aes256Gcm;
            var combined = AeadAlgorithm.Aes256Gcm;

            var keyBlobFmt = KeyBlobFormat.NSecSymmetricKey;

            using var detachedK = new Key(detached, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport});
            var n = Utilities.RandomBytes[..detached.NonceSize];
            Assert.Equal(combined.NonceSize, n.Length);
            var ad = Utilities.RandomBytes[..100];

            var expected = Utilities.RandomBytes[..length].ToArray();

            Span<byte> ciphertext = new byte[length];
            Span<byte> tag = new byte[detached.TagSize];
            Assert.Equal(combined.TagSize, tag.Length);

            detached.Encrypt(detachedK, n, ad, expected, ciphertext, tag);

            Span<byte> keyBlob = new byte[detachedK.GetExportBlobSize(keyBlobFmt)];

            var exportResult = detached.TryExportKey(detachedK.Handle, keyBlobFmt, keyBlob, out int blobsize);
            Assert.True(exportResult);
            Assert.Equal(keyBlob.Length, blobsize);

            var importResult = Key.TryImport(AeadAlgorithm.Aes256Gcm, keyBlob, keyBlobFmt, out var combinedK);
            Assert.True(importResult);
            Assert.NotNull(combinedK);
            Assert.Equal(combined.KeySize, combinedK?.Size);

            var combinedCiphertext = new byte[length + combined.TagSize];
            Assert.Equal(ciphertext.Length + combined.TagSize, combinedCiphertext.Length);
            Array.Copy(ciphertext.ToArray(), combinedCiphertext, ciphertext.Length);
            Array.Copy(tag.ToArray(), 0, combinedCiphertext, ciphertext.Length, tag.Length);

            var actual = combined.Decrypt(combinedK, n, ad, combinedCiphertext);
            Assert.NotNull(actual);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(PlaintextLengths))]
        public static void EncryptCombinedDecryptDetached(int length)
        {
            var combined = AeadAlgorithm.Aes256Gcm;
            var detached = AeadDetachedAlgorithm.Aes256Gcm;

            var keyBlobFmt = KeyBlobFormat.NSecSymmetricKey;

            using var combinedK = new Key(combined, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var n = Utilities.RandomBytes[..combined.NonceSize];
            var ad = Utilities.RandomBytes[..100];

            var expected = Utilities.RandomBytes[..length].ToArray();

            var ciphertext = combined.Encrypt(combinedK, n, ad, expected);
            Assert.NotNull(ciphertext);
            Assert.Equal(length + combined.TagSize, ciphertext.Length);

            Span<byte> detachedCiphertext = new Span<byte>(ciphertext, 0, length);
            Span<byte> tag = new Span<byte>(ciphertext, length, combined.TagSize);

            Span<byte> keyBlob = new byte[combinedK.GetExportBlobSize(keyBlobFmt)];

            var exportResult = combined.TryExportKey(combinedK.Handle, keyBlobFmt, keyBlob, out var blobSize);
            Assert.True(exportResult);
            Assert.Equal(keyBlob.Length, blobSize);

            var importResult = Key.TryImport(AeadDetachedAlgorithm.Aes256Gcm, keyBlob, keyBlobFmt, out var detachedK);
            Assert.True(importResult);
            Assert.NotNull(detachedK);
            Assert.Equal(detached.KeySize, detachedK?.Size);

            Span<byte> actual = new byte[length];

            var decryptResult = detached.Decrypt(detachedK, n, ad, detachedCiphertext, tag, actual);
            Assert.True(decryptResult);
            Assert.Equal(expected, actual);
        }

        #endregion
    }
}
