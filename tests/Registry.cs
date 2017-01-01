using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests
{
    internal static class Registry
    {
        #region Algorithms By Base Class

        public static readonly TheoryData<Type> AeadAlgorithms = Aes256Gcm.IsAvailable
            ? new TheoryData<Type>
        {
            typeof(Aes256Gcm),
            typeof(ChaCha20Poly1305),
        }
            : new TheoryData<Type>
        {
            typeof(ChaCha20Poly1305),
        };

        public static readonly TheoryData<Type> AuthenticationAlgorithms = new TheoryData<Type>
        {
            typeof(HmacSha256),
            typeof(HmacSha512),
        };

        public static readonly TheoryData<Type> HashAlgorithms = new TheoryData<Type>
        {
            typeof(Sha256),
            typeof(Sha512),
        };

        public static readonly TheoryData<Type> KeyAgreementAlgorithms = new TheoryData<Type>
        {
            typeof(X25519),
        };

        public static readonly TheoryData<Type> KeyDerivationAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> SignatureAlgorithms = new TheoryData<Type>
        {
            typeof(Ed25519),
        };

        #endregion

        #region Algorithms By Key Type

        public static readonly TheoryData<Type> AsymmetricAlgorithms = new TheoryData<Type>
        {
            typeof(X25519),
            typeof(Ed25519),
        };

        public static readonly TheoryData<Type> SymmetricAlgorithms = Aes256Gcm.IsAvailable
            ? new TheoryData<Type>
        {
            typeof(Aes256Gcm),
            typeof(ChaCha20Poly1305),
            typeof(HmacSha256),
            typeof(HmacSha512),
        }
            : new TheoryData<Type>
        {
            typeof(ChaCha20Poly1305),
            typeof(HmacSha256),
            typeof(HmacSha512),
        };

        public static readonly TheoryData<Type> KeylessAlgorithms = new TheoryData<Type>
        {
            typeof(Sha256),
            typeof(Sha512),
        };

        #endregion

        #region Key Blob Formats

        public static readonly TheoryData<Type, KeyBlobFormat> PublicKeyBlobFormats = new TheoryData<Type, KeyBlobFormat>
        {
            { typeof(X25519), KeyBlobFormat.RawPublicKey },
            { typeof(X25519), KeyBlobFormat.NSecPublicKey },
            { typeof(X25519), KeyBlobFormat.PkixPublicKey },
            { typeof(X25519), KeyBlobFormat.PkixPublicKeyText },
            { typeof(Ed25519), KeyBlobFormat.RawPublicKey },
            { typeof(Ed25519), KeyBlobFormat.NSecPublicKey },
            { typeof(Ed25519), KeyBlobFormat.PkixPublicKey },
            { typeof(Ed25519), KeyBlobFormat.PkixPublicKeyText },
        };

        public static readonly TheoryData<Type, KeyBlobFormat> PrivateKeyBlobFormats = new TheoryData<Type, KeyBlobFormat>
        {
            { typeof(X25519), KeyBlobFormat.RawPrivateKey },
            { typeof(X25519), KeyBlobFormat.NSecPublicKey },
            { typeof(X25519), KeyBlobFormat.PkixPrivateKey },
            { typeof(X25519), KeyBlobFormat.PkixPrivateKeyText },
            { typeof(Ed25519), KeyBlobFormat.RawPrivateKey },
            { typeof(Ed25519), KeyBlobFormat.NSecPrivateKey },
            { typeof(Ed25519), KeyBlobFormat.PkixPrivateKey },
            { typeof(Ed25519), KeyBlobFormat.PkixPrivateKeyText },
        };

        public static readonly TheoryData<Type, KeyBlobFormat> SymmetricKeyBlobFormats = Aes256Gcm.IsAvailable
            ? new TheoryData<Type, KeyBlobFormat>
        {
            { typeof(Aes256Gcm), KeyBlobFormat.RawSymmetricKey },
            { typeof(Aes256Gcm), KeyBlobFormat.NSecSymmetricKey },
            { typeof(ChaCha20Poly1305), KeyBlobFormat.RawSymmetricKey },
            { typeof(ChaCha20Poly1305), KeyBlobFormat.NSecSymmetricKey },
            { typeof(HmacSha256), KeyBlobFormat.RawSymmetricKey },
            { typeof(HmacSha512), KeyBlobFormat.RawSymmetricKey },
        }
            : new TheoryData<Type, KeyBlobFormat>
        {
            { typeof(ChaCha20Poly1305), KeyBlobFormat.RawSymmetricKey },
            { typeof(ChaCha20Poly1305), KeyBlobFormat.NSecSymmetricKey },
            { typeof(HmacSha256), KeyBlobFormat.RawSymmetricKey },
            { typeof(HmacSha512), KeyBlobFormat.RawSymmetricKey },
        };

        #endregion
    }
}
