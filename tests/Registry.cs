using System;
using NSec.Cryptography;
using NSec.Experimental;
using Xunit;

namespace NSec.Tests
{
    internal static class Registry
    {
        #region Algorithms By Base Class

        public static readonly TheoryData<Type> AeadAlgorithms = new TheoryData<Type>
        {
            typeof(Aes256Gcm),
            typeof(ChaCha20Poly1305),
        };

        public static readonly TheoryData<Type> MacAlgorithms = new TheoryData<Type>
        {
            typeof(Blake2bMac),
            typeof(HmacSha256),
            typeof(HmacSha512),
        };

        public static readonly TheoryData<Type> HashAlgorithms = new TheoryData<Type>
        {
            typeof(Blake2b),
            typeof(Sha256),
            typeof(Sha512),
        };

        public static readonly TheoryData<Type> KeyAgreementAlgorithms = new TheoryData<Type>
        {
            typeof(X25519),
        };

        public static readonly TheoryData<Type> KeyDerivationAlgorithms = new TheoryData<Type>
        {
            typeof(AnsiX963KdfSha256),
            typeof(ConcatKdfHmacSha256),
            typeof(ConcatKdfSha256),
            typeof(HkdfSha256),
            typeof(HkdfSha512),
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

        public static readonly TheoryData<Type> SymmetricAlgorithms = new TheoryData<Type>
        {
            typeof(Aes256Gcm),
            typeof(Blake2bMac),
            typeof(ChaCha20Poly1305),
            typeof(HmacSha256),
            typeof(HmacSha512),
        };

        public static readonly TheoryData<Type> KeylessAlgorithms = new TheoryData<Type>
        {
            typeof(Blake2b),
            typeof(AnsiX963KdfSha256),
            typeof(ConcatKdfHmacSha256),
            typeof(ConcatKdfSha256),
            typeof(HkdfSha256),
            typeof(HkdfSha512),
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
            { typeof(X25519), KeyBlobFormat.NSecPrivateKey },
            { typeof(X25519), KeyBlobFormat.PkixPrivateKey },
            { typeof(X25519), KeyBlobFormat.PkixPrivateKeyText },
            { typeof(Ed25519), KeyBlobFormat.RawPrivateKey },
            { typeof(Ed25519), KeyBlobFormat.NSecPrivateKey },
            { typeof(Ed25519), KeyBlobFormat.PkixPrivateKey },
            { typeof(Ed25519), KeyBlobFormat.PkixPrivateKeyText },
        };

        public static readonly TheoryData<Type, KeyBlobFormat> SymmetricKeyBlobFormats = new TheoryData<Type, KeyBlobFormat>
        {
            { typeof(Aes256Gcm), KeyBlobFormat.RawSymmetricKey },
            { typeof(Aes256Gcm), KeyBlobFormat.NSecSymmetricKey },
            { typeof(Blake2bMac), KeyBlobFormat.RawSymmetricKey },
            { typeof(Blake2bMac), KeyBlobFormat.NSecSymmetricKey },
            { typeof(ChaCha20Poly1305), KeyBlobFormat.RawSymmetricKey },
            { typeof(ChaCha20Poly1305), KeyBlobFormat.NSecSymmetricKey },
            { typeof(HmacSha256), KeyBlobFormat.RawSymmetricKey },
            { typeof(HmacSha256), KeyBlobFormat.NSecSymmetricKey },
            { typeof(HmacSha512), KeyBlobFormat.RawSymmetricKey },
            { typeof(HmacSha512), KeyBlobFormat.NSecSymmetricKey },
        };

        #endregion
    }
}
