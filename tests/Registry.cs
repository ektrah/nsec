using System;
using NSec.Cryptography;
using NSec.Experimental;
using NSec.Experimental.PasswordBased;
using Xunit;

namespace NSec.Tests
{
    internal static class Registry
    {
        #region Algorithms By Base Class

        public static readonly TheoryData<AeadAlgorithm> AeadAlgorithms = new()
        {
            AeadAlgorithm.Aegis128L,
            AeadAlgorithm.Aegis256,
            AeadAlgorithm.Aes256Gcm,
            AeadAlgorithm.ChaCha20Poly1305,
            AeadAlgorithm.XChaCha20Poly1305,
        };

        public static readonly TheoryData<MacAlgorithm> MacAlgorithms = new()
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
            new HmacSha512(32, 32),
        };

        public static readonly TheoryData<StreamCipherAlgorithm> StreamCipherAlgorithms = new()
        {
            StreamCipherAlgorithm.ChaCha20
        };

        public static readonly TheoryData<HashAlgorithm> HashAlgorithms = new()
        {
            HashAlgorithm.Blake2b_256,
            HashAlgorithm.Blake2b_512,
            HashAlgorithm.Sha256,
            HashAlgorithm.Sha512,
            HashAlgorithm.Sha512_256,
        };

        public static readonly TheoryData<KeyAgreementAlgorithm> KeyAgreementAlgorithms = new()
        {
            KeyAgreementAlgorithm.X25519,
        };

        public static readonly TheoryData<KeyDerivationAlgorithm> KeyDerivationAlgorithms = new()
        {
            new AnsiX963KdfSha256(),
            new ConcatKdfHmacSha256(),
            new ConcatKdfSha256(),
            KeyDerivationAlgorithm.HkdfSha256,
            KeyDerivationAlgorithm.HkdfSha512,
        };

        public static readonly TheoryData<KeyDerivationAlgorithm2> KeyDerivationAlgorithms2 = new()
        {
            KeyDerivationAlgorithm2.HkdfSha256,
            KeyDerivationAlgorithm2.HkdfSha512,
        };

        public static readonly TheoryData<PasswordBasedKeyDerivationAlgorithm> PasswordHashAlgorithms = new()
        {
            // intentionally weak parameters for unit testing
            new Argon2i(new Argon2Parameters { DegreeOfParallelism = 1, MemorySize = 1 << 12, NumberOfPasses = 3 }),
            PasswordBasedKeyDerivationAlgorithm.Argon2id(new Argon2Parameters { DegreeOfParallelism = 1, MemorySize = 1 << 12, NumberOfPasses = 3 }),
            PasswordBasedKeyDerivationAlgorithm.Scrypt(new ScryptParameters { Cost = 1 << 11, BlockSize = 5, Parallelization = 1 }),
            new Pbkdf2HmacSha256(new Pbkdf2Parameters { IterationCount = 10 }),
        };

        public static readonly TheoryData<SignatureAlgorithm> SignatureAlgorithms = new()
        {
            SignatureAlgorithm.Ed25519,
            SignatureAlgorithm.Ed25519ph,
        };

        public static readonly TheoryData<SignatureAlgorithm2> IncrementalSignatureAlgorithms = new()
        {
            SignatureAlgorithm.Ed25519ph,
        };

        #endregion

        #region Algorithms By Key Type

        public static readonly TheoryData<Algorithm> AsymmetricAlgorithms = new()
        {
            KeyAgreementAlgorithm.X25519,
            SignatureAlgorithm.Ed25519,
            SignatureAlgorithm.Ed25519ph,
        };

        public static readonly TheoryData<Algorithm> SymmetricAlgorithms = new()
        {
            AeadAlgorithm.Aegis128L,
            AeadAlgorithm.Aegis256,
            AeadAlgorithm.Aes256Gcm,
            AeadAlgorithm.ChaCha20Poly1305,
            AeadAlgorithm.XChaCha20Poly1305,
            MacAlgorithm.Blake2b_128,
            MacAlgorithm.Blake2b_256,
            MacAlgorithm.Blake2b_512,
            MacAlgorithm.HmacSha256,
            MacAlgorithm.HmacSha256_128,
            MacAlgorithm.HmacSha512,
            MacAlgorithm.HmacSha512_256,
            StreamCipherAlgorithm.ChaCha20,
        };

        public static readonly TheoryData<Algorithm> KeylessAlgorithms = new()
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
            // intentionally weak parameters for unit testing
            new Argon2i(new Argon2Parameters { DegreeOfParallelism = 1, MemorySize = 1 << 12, NumberOfPasses = 3 }),
            PasswordBasedKeyDerivationAlgorithm.Argon2id(new Argon2Parameters { DegreeOfParallelism = 1, MemorySize = 1 << 12, NumberOfPasses = 3 }),
            PasswordBasedKeyDerivationAlgorithm.Scrypt(new ScryptParameters { Cost = 1 << 11, BlockSize = 5, Parallelization = 1 }),
            new Pbkdf2HmacSha256(new Pbkdf2Parameters { IterationCount = 10 }),
        };

        #endregion

        #region Key Blob Formats

        public static readonly TheoryData<Algorithm, KeyBlobFormat> PublicKeyBlobFormats = new()
        {
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.RawPublicKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.NSecPublicKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.PkixPublicKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.PkixPublicKeyText },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.RawPublicKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.NSecPublicKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.PkixPublicKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.PkixPublicKeyText },
            { SignatureAlgorithm.Ed25519ph, KeyBlobFormat.RawPublicKey },
            { SignatureAlgorithm.Ed25519ph, KeyBlobFormat.NSecPublicKey },
        };

        public static readonly TheoryData<Algorithm, KeyBlobFormat> PrivateKeyBlobFormats = new()
        {
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.RawPrivateKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.NSecPrivateKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.PkixPrivateKey },
            { KeyAgreementAlgorithm.X25519, KeyBlobFormat.PkixPrivateKeyText },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.RawPrivateKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.NSecPrivateKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.PkixPrivateKey },
            { SignatureAlgorithm.Ed25519, KeyBlobFormat.PkixPrivateKeyText },
            { SignatureAlgorithm.Ed25519ph, KeyBlobFormat.RawPrivateKey },
            { SignatureAlgorithm.Ed25519ph, KeyBlobFormat.NSecPrivateKey },
        };

        public static readonly TheoryData<Algorithm, KeyBlobFormat> SymmetricKeyBlobFormats = new()
        {
            { AeadAlgorithm.Aegis128L, KeyBlobFormat.RawSymmetricKey },
            { AeadAlgorithm.Aegis128L, KeyBlobFormat.NSecSymmetricKey },
            { AeadAlgorithm.Aegis256, KeyBlobFormat.RawSymmetricKey },
            { AeadAlgorithm.Aegis256, KeyBlobFormat.NSecSymmetricKey },
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
            { AeadAlgorithm.XChaCha20Poly1305, KeyBlobFormat.RawSymmetricKey },
            { AeadAlgorithm.XChaCha20Poly1305, KeyBlobFormat.NSecSymmetricKey },
        };

        #endregion

        #region SharedSecret Blob Formats

        public static readonly TheoryData<SharedSecretBlobFormat> SharedSecretBlobFormats = new()
        {
            SharedSecretBlobFormat.RawSharedSecret,
            SharedSecretBlobFormat.NSecSharedSecret,
        };

        #endregion
    }
}
