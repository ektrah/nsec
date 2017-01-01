using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests
{
    internal static class Registry
    {
        #region Algorithms By Base Class

        public static readonly TheoryData<Type> AeadAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> AuthenticationAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> HashAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> KeyAgreementAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> KeyDerivationAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> PasswordHashAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> SignatureAlgorithms = new TheoryData<Type>
        {
        };

        #endregion

        #region Algorithms By Key Type

        public static readonly TheoryData<Type> AsymmetricAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> SymmetricAlgorithms = new TheoryData<Type>
        {
        };

        public static readonly TheoryData<Type> KeylessAlgorithms = new TheoryData<Type>
        {
        };

        #endregion

        #region Key Blob Formats

        public static readonly TheoryData<Type, KeyBlobFormat> PublicKeyBlobFormats = new TheoryData<Type, KeyBlobFormat>
        {
        };

        public static readonly TheoryData<Type, KeyBlobFormat> PrivateKeyBlobFormats = new TheoryData<Type, KeyBlobFormat>
        {
        };

        public static readonly TheoryData<Type, KeyBlobFormat> SymmetricKeyBlobFormats = new TheoryData<Type, KeyBlobFormat>
        {
        };

        #endregion
    }
}
