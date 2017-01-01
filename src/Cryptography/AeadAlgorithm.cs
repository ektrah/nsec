using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
    public abstract class AeadAlgorithm : Algorithm
    {
        private readonly int _keySize;
        private readonly int _nonceSize;
        private readonly int _tagSize;

        internal AeadAlgorithm(
            int keySize,
            int nonceSize,
            int tagSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(nonceSize > 0);
            Debug.Assert(tagSize > 0);

            _keySize = keySize;
            _nonceSize = nonceSize;
            _tagSize = tagSize;
        }

        public int KeySize => _keySize;

        public int NonceSize => _nonceSize;

        public int TagSize => _tagSize;

        public byte[] Decrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (nonce.Length != _nonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (ciphertext.Length < _tagSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(ciphertext));

            byte[] plaintext = new byte[ciphertext.Length - _tagSize];

            if (!TryDecryptCore(key, nonce, associatedData, ciphertext, plaintext))
            {
                throw new CryptographicException();
            }

            return plaintext;
        }

        public void Decrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (nonce.Length != _nonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (ciphertext.Length < _tagSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(ciphertext));
            if (plaintext.Length != ciphertext.Length - _tagSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(plaintext));

            if (!TryDecryptCore(key, nonce, associatedData, ciphertext, plaintext))
            {
                throw new CryptographicException();
            }
        }

        public byte[] Encrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (nonce.Length != _nonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (int.MaxValue - plaintext.Length < _tagSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(plaintext));

            byte[] ciphertext = new byte[plaintext.Length + _tagSize];
            EncryptCore(key, nonce, associatedData, plaintext, ciphertext);
            return ciphertext;
        }

        public void Encrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (nonce.Length != _nonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (int.MaxValue - plaintext.Length < _tagSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(plaintext));
            if (ciphertext.Length != plaintext.Length + _tagSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(ciphertext));

            EncryptCore(key, nonce, associatedData, plaintext, ciphertext);
        }

        public bool TryDecrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            out byte[] plaintext)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (nonce.Length != _nonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));

            if (ciphertext.Length < _tagSize)
            {
                plaintext = null;
                return false;
            }

            byte[] result = new byte[ciphertext.Length - _tagSize];

            if (!TryDecryptCore(key, nonce, associatedData, ciphertext, result))
            {
                plaintext = null;
                return false;
            }

            plaintext = result;
            return true;
        }

        public bool TryDecrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (nonce.Length != _nonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (ciphertext.Length < _tagSize)
                return false;
            if (plaintext.Length != ciphertext.Length - _tagSize)
                return false;

            return TryDecryptCore(key, nonce, associatedData, ciphertext, plaintext);
        }

        internal abstract void EncryptCore(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext);

        internal abstract bool TryDecryptCore(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext);
    }
}
