using System;
using NSec.Cryptography;
using NSec.Experimental.PasswordBased;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class PasswordBasedKeyExporterTests
    {
        public static readonly TheoryData<PasswordBasedKeyDerivationAlgorithm> PasswordHashAlgorithms = Registry.PasswordHashAlgorithms;

        private const string s_password = "passw0rd123";

        #region Export

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void ExportWithNullKey(PasswordBasedKeyDerivationAlgorithm a)
        {
            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentNullException>("key", () => PasswordBasedKeyExporter.Export(null!, scheme, Utilities.RandomBytes[..128], Utilities.RandomBytes[..scheme.MinSaltSize], Utilities.RandomBytes[..scheme.NonceSize]));
        }

        [Fact]
        public static void ExportWithNullScheme()
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            Assert.Throws<ArgumentNullException>("scheme", () => PasswordBasedKeyExporter.Export(k, null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void ExportWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentException>("salt", () => PasswordBasedKeyExporter.Export(k, scheme, Utilities.RandomBytes[..128], Utilities.RandomBytes[..(scheme.MinSaltSize - 1)], Utilities.RandomBytes[..scheme.NonceSize]));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void ExportWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentException>("salt", () => PasswordBasedKeyExporter.Export(k, scheme, Utilities.RandomBytes[..128], Utilities.RandomBytes[..(scheme.MinSaltSize + 1)], Utilities.RandomBytes[..scheme.NonceSize]));
        }


        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void ExportWithNonceTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentException>("nonce", () => PasswordBasedKeyExporter.Export(k, scheme, Utilities.RandomBytes[..128], Utilities.RandomBytes[..scheme.MinSaltSize], Utilities.RandomBytes[..(scheme.NonceSize - 1)]));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void ExportWithNonceTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentException>("nonce", () => PasswordBasedKeyExporter.Export(k, scheme, Utilities.RandomBytes[..128], Utilities.RandomBytes[..scheme.MinSaltSize], Utilities.RandomBytes[..(scheme.NonceSize + 1)]));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void ExportImportSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var expected = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);
            var password = Utilities.RandomBytes[..128];
            var salt = Utilities.RandomBytes[..scheme.MinSaltSize];
            var nonce = Utilities.RandomBytes[..scheme.NonceSize];

            var encrypted = PasswordBasedKeyExporter.Export(expected, scheme, password, salt, nonce);

            var actual = PasswordBasedKeyExporter.Import(expected.Algorithm, encrypted, scheme, password, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            Assert.Equal(expected.Export(KeyBlobFormat.NSecPrivateKey), actual.Export(KeyBlobFormat.NSecPrivateKey));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringExportWithNullKey(PasswordBasedKeyDerivationAlgorithm a)
        {
            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentNullException>("key", () => PasswordBasedKeyExporter.Export(null!, scheme, s_password, Utilities.RandomBytes[..scheme.MinSaltSize], Utilities.RandomBytes[..scheme.NonceSize]));
        }

        [Fact]
        public static void StringExportWithNullScheme()
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            Assert.Throws<ArgumentNullException>("scheme", () => PasswordBasedKeyExporter.Export(k, null!, s_password, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringExportWithNullPassword(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentNullException>("password", () => PasswordBasedKeyExporter.Export(k, scheme, (string)null!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringExportWithSaltTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentException>("salt", () => PasswordBasedKeyExporter.Export(k, scheme, s_password, Utilities.RandomBytes[..(scheme.MinSaltSize - 1)], Utilities.RandomBytes[..scheme.NonceSize]));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringExportWithSaltTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentException>("salt", () => PasswordBasedKeyExporter.Export(k, scheme, s_password, Utilities.RandomBytes[..(scheme.MinSaltSize + 1)], Utilities.RandomBytes[..scheme.NonceSize]));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringExportWithNonceTooShort(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentException>("nonce", () => PasswordBasedKeyExporter.Export(k, scheme, s_password, Utilities.RandomBytes[..scheme.MinSaltSize], Utilities.RandomBytes[..(scheme.NonceSize - 1)]));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringExportWithNonceTooLarge(PasswordBasedKeyDerivationAlgorithm a)
        {
            var k = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);

            Assert.Throws<ArgumentException>("nonce", () => PasswordBasedKeyExporter.Export(k, scheme, s_password, Utilities.RandomBytes[..scheme.MinSaltSize], Utilities.RandomBytes[..(scheme.NonceSize + 1)]));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringExportImportSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var expected = new Key(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);
            var password = s_password;
            var salt = Utilities.RandomBytes[..scheme.MinSaltSize];
            var nonce = Utilities.RandomBytes[..scheme.NonceSize];

            var encrypted = PasswordBasedKeyExporter.Export(expected, scheme, password, salt, nonce);

            var actual = PasswordBasedKeyExporter.Import(expected.Algorithm, encrypted, scheme, password, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            Assert.Equal(expected.Export(KeyBlobFormat.NSecPrivateKey), actual.Export(KeyBlobFormat.NSecPrivateKey));
        }

        #endregion

        #region Encrypt

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

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void StringEncryptDecryptSuccess(PasswordBasedKeyDerivationAlgorithm a)
        {
            var expected = Utilities.RandomBytes[0..128].ToArray();

            var scheme = new PasswordBasedEncryptionScheme(a, AeadAlgorithm.ChaCha20Poly1305);
            var password = s_password;
            var salt = Utilities.RandomBytes[..scheme.MinSaltSize];
            var nonce = Utilities.RandomBytes[..scheme.NonceSize];

            var encrypted = PasswordBasedKeyExporter.Encrypt(expected, scheme, password, salt, nonce);

            var actual = PasswordBasedKeyExporter.Decrypt(encrypted, scheme, password);

            Assert.Equal(expected, actual);
        }

        #endregion
    }
}
