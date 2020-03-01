using System;
using NSec.Cryptography;

namespace NSec.Experimental.PasswordBased
{
    //
    //  PBES2
    //
    //      Password-Based Encryption Scheme
    //
    //  References
    //
    //      RFC 8018 - PKCS #5: Password-Based Cryptography Specification
    //          Version 2.1
    //
    //  Parameters
    //
    //      PBES2 combines a password-based key derivation function with an
    //      encryption algorithm. The parameters depend on the primitives
    //      combined.
    //
    public sealed class PasswordBasedEncryptionScheme
    {
        private readonly AeadAlgorithm _encryptionAlgorithm;
        private readonly PasswordBasedKeyDerivationAlgorithm _keyDerivationAlgorithm;

        public PasswordBasedEncryptionScheme(
            PasswordBasedKeyDerivationAlgorithm keyDerivationAlgorithm,
            AeadAlgorithm encryptionAlgorithm)
        {
            if (keyDerivationAlgorithm == null)
                throw new ArgumentNullException(nameof(keyDerivationAlgorithm));
            if (encryptionAlgorithm == null)
                throw new ArgumentNullException(nameof(encryptionAlgorithm));

            _keyDerivationAlgorithm = keyDerivationAlgorithm;
            _encryptionAlgorithm = encryptionAlgorithm;
        }

        public AeadAlgorithm EncryptionAlgorithm => _encryptionAlgorithm;

        public PasswordBasedKeyDerivationAlgorithm KeyDerivationAlgorithm => _keyDerivationAlgorithm;

        public int NonceSize => _encryptionAlgorithm.NonceSize;

        public int SaltSize => _keyDerivationAlgorithm.SaltSize;

        public int TagSize => _encryptionAlgorithm.TagSize;

        public byte[] Encrypt(
            string password,
            ReadOnlySpan<byte> salt,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext)
        {
            using Key key = _keyDerivationAlgorithm.DeriveKey(password, salt, _encryptionAlgorithm);
            return _encryptionAlgorithm.Encrypt(key, nonce, default, plaintext);
        }

        public void Encrypt(
            string password,
            ReadOnlySpan<byte> salt,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            using Key key = _keyDerivationAlgorithm.DeriveKey(password, salt, _encryptionAlgorithm);
            _encryptionAlgorithm.Encrypt(key, nonce, default, plaintext, ciphertext);
        }

        public bool Decrypt(
            string password,
            ReadOnlySpan<byte> salt,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            out byte[]? plaintext)
        {
            using Key key = _keyDerivationAlgorithm.DeriveKey(password, salt, _encryptionAlgorithm);
            return _encryptionAlgorithm.Decrypt(key, nonce, default, ciphertext, out plaintext);
        }

        public bool Decrypt(
            string password,
            ReadOnlySpan<byte> salt,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            using Key key = _keyDerivationAlgorithm.DeriveKey(password, salt, _encryptionAlgorithm);
            return _encryptionAlgorithm.Decrypt(key, nonce, default, ciphertext, plaintext);
        }
    }
}
