using System;
using NSec.Cryptography;
using NSec.Experimental.PasswordBased;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class PasswordBasedKeyExporterTests
    {
        public static readonly TheoryData<PasswordBasedKeyDerivationAlgorithm> PasswordHashAlgorithms = Registry.PasswordHashAlgorithms;

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void EncryptDecryptSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var expected = Utilities.RandomBytes[0..128].ToArray();

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);
            var password = Utilities.RandomBytes[128..160];
            var salt = Utilities.RandomBytes[..scheme.MinSaltSize];
            var nonce = Utilities.RandomBytes[..scheme.NonceSize];

            var encrypted = PasswordBasedKeyExporter.Encrypt(expected, scheme, password, salt, nonce);

            var actual = PasswordBasedKeyExporter.Decrypt(encrypted, scheme, password);

            Assert.Equal(expected, actual);
        }
    }
}
