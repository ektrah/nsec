using System;
using NSec.Cryptography;
using NSec.Experimental;
using NSec.Experimental.PasswordBased;
using NSec.Experimental.Sodium;
using Xunit;

namespace NSec.Tests
{
    internal static class Registry
    {
        #region Algorithms By Base Class

        public static readonly TheoryData<AeadAlgorithm> AeadAlgorithms = new TheoryData<AeadAlgorithm>
        {
            AeadAlgorithm.Aes256Gcm,
            AeadAlgorithm.ChaCha20Poly1305,
            new XChaCha20Poly1305(),
        };

        public static readonly TheoryData<MacAlgorithm> MacAlgorithms = new TheoryData<MacAlgorithm>
        {
            new Blake2bMac(16, 16),
            new Blake2bMac(16, 32),
            new Blake2bMac(16, 64),
            MacAlgorithm.Blake2b_128,
            MacAlgorithm.Blake2b_256,
            MacAlgorithm.Blake2b_512,
            new Blake2bMac(64, 16),
            new Blake2bMac(64, 32),
            new Blake2bMac(64, 64),
            MacAlgorithm.HmacSha256,
            MacAlgorithm.HmacSha256_128,
            MacAlgorithm.HmacSha512,
            MacAlgorithm.HmacSha512_256,
        };

        public static readonly TheoryData<StreamCipherAlgorithm> StreamCipherAlgorithms = new TheoryData<StreamCipherAlgorithm>
        {
            StreamCipherAlgorithm.ChaCha20
        };

        public static readonly TheoryData<HashAlgorithm> HashAlgorithms = new TheoryData<HashAlgorithm>
        {
            HashAlgorithm.Blake2b_256,
            HashAlgorithm.Blake2b_512,
            HashAlgorithm.Sha256,
            HashAlgorithm.Sha512,
            HashAlgorithm.Sha512_256,
        };

        public static readonly TheoryData<KeyAgreementAlgorithm> KeyAgreementAlgorithms = new TheoryData<KeyAgreementAlgorithm>
        {
            KeyAgreementAlgorithm.X25519,
        };

        public static readonly TheoryData<KeyDerivationAlgorithm> KeyDerivationAlgorithms = new TheoryData<KeyDerivationAlgorithm>
        {
            new AnsiX963KdfSha256(),
            new ConcatKdfHmacSha256(),
            new ConcatKdfSha256(),
            KeyDerivationAlgorithm.HkdfSha256,
            KeyDerivationAlgorithm.HkdfSha512,
        };

        public static readonly TheoryData<PasswordBasedKeyDerivationAlgorithm> PasswordHashAlgorithms = new TheoryData<PasswordBasedKeyDerivationAlgorithm>
        {
            // intentionally weak parameters for unit tests
            new Argon2i(1, 1 << 12, 3),
            new Argon2id(1, 1 << 12, 3),
            new Scrypt(1 << 11, 5, 1),
            new Pbkdf2HmacSha256(10),
        };

        public static readonly TheoryData<SignatureAlgorithm> SignatureAlgorithms = new TheoryData<SignatureAlgorithm>
        {
            SignatureAlgorithm.Ed25519,
        };

        #endregion

        #region Algorithms By Key Type

        public static readonly TheoryData<Algorithm> AsymmetricAlgorithms = new TheoryData<Algorithm>
        {
            KeyAgreementAlgorithm.X25519,
            SignatureAlgorithm.Ed25519,
        };

        public static readonly TheoryData<Algorithm> SymmetricAlgorithms = new TheoryData<Algorithm>
        {
            AeadAlgorithm.Aes256Gcm,
            AeadAlgorithm.ChaCha20Poly1305,
            new XChaCha20Poly1305(),
            MacAlgorithm.Blake2b_128,
            MacAlgorithm.Blake2b_256,
            MacAlgorithm.Blake2b_512,
            MacAlgorithm.HmacSha256,
            MacAlgorithm.HmacSha256_128,
            MacAlgorithm.HmacSha512,
            MacAlgorithm.HmacSha512_256,
            StreamCipherAlgorithm.ChaCha20,
        };

        public static readonly TheoryData<Algorithm> KeylessAlgorithms = new TheoryData<Algorithm>
        {
            HashAlgorithm.Blake2b_256,
            HashAlgorithm.Blake2b_512,
            HashAlgorithm.Sha256,
            HashAlgorithm.Sha512,
            HashAlgorithm.Sha512_256,
            new AnsiX963KdfSha256(),
            new ConcatKdfHmacSha256(),
            new ConcatKdfSha256(),
            KeyDerivationAlgorithm.HkdfSha256,
            KeyDerivationAlgorithm.HkdfSha512,
            // intentionally weak parameters for unit tests
            new Argon2i(1, 1 << 12, 3),
            new Argon2id(1, 1 << 12, 3),
            new Scrypt(1 << 11, 5, 1),
            new Pbkdf2HmacSha256(10),
        };

        #endregion

        #region Key Blob Formats

        public static readonly TheoryData<Algorithm, KeyBlobFormat> PublicKeyBlobFormats = new TheoryData<Algorithm, KeyBlobFormat>
        {
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.RawPublicKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.NSecPublicKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.PkixPublicKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.PkixPublicKeyText },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.RawPublicKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.NSecPublicKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.PkixPublicKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.PkixPublicKeyText },
        };

        public static readonly TheoryData<Algorithm, KeyBlobFormat> PrivateKeyBlobFormats = new TheoryData<Algorithm, KeyBlobFormat>
        {
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.RawPrivateKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.NSecPrivateKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.PkixPrivateKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.PkixPrivateKeyText },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.RawPrivateKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.NSecPrivateKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.PkixPrivateKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.PkixPrivateKeyText },
        };

        public static readonly TheoryData<Algorithm, KeyBlobFormat> SymmetricKeyBlobFormats = new TheoryData<Algorithm, KeyBlobFormat>
        {
            { AeadAlgorithm.Aes256Gcm, KeyBlobFormat.RawSymmetricKey },
            { AeadAlgorithm.Aes256Gcm, KeyBlobFormat.NSecSymmetricKey },
            { MacAlgorithm.Blake2b_128, KeyBlobFormat.RawSymmetricKey },
            { MacAlgorithm.Blake2b_128, KeyBlobFormat.NSecSymmetricKey },
            { MacAlgorithm.Blake2b_256, KeyBlobFormat.RawSymmetricKey },
            { MacAlgorithm.Blake2b_256, KeyBlobFormat.NSecSymmetricKey },
            { MacAlgorithm.Blake2b_512, KeyBlobFormat.RawSymmetricKey },
            { MacAlgorithm.Blake2b_512, KeyBlobFormat.NSecSymmetricKey },
            { AeadAlgorithm.ChaCha20Poly1305, KeyBlobFormat.RawSymmetricKey },
            { AeadAlgorithm.ChaCha20Poly1305, KeyBlobFormat.NSecSymmetricKey },
            { StreamCipherAlgorithm.ChaCha20, KeyBlobFormat.RawSymmetricKey },
            { MacAlgorithm.HmacSha256, KeyBlobFormat.RawSymmetricKey },
            { MacAlgorithm.HmacSha256, KeyBlobFormat.NSecSymmetricKey },
            { MacAlgorithm.HmacSha512, KeyBlobFormat.RawSymmetricKey },
            { MacAlgorithm.HmacSha512, KeyBlobFormat.NSecSymmetricKey },
            { new XChaCha20Poly1305(), KeyBlobFormat.RawSymmetricKey },
            { new XChaCha20Poly1305(), KeyBlobFormat.NSecSymmetricKey },
        };

        #endregion
    }
}
