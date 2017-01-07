using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
    //
    //  An authenticated encryption with associated data (AEAD) algorithm
    //
    //  Examples
    //
    //      | Algorithm         | Reference | Key Size | Nonce Size | Tag Size |
    //      | ----------------- | --------- | -------- | ---------- | -------- |
    //      | AES_128_CCM       | RFC 5116  | 16       | 12         | 16       |
    //      | AES_256_CCM       | RFC 5116  | 32       | 12         | 16       |
    //      | AES_128_GCM       | RFC 5116  | 16       | 12         | 16       |
    //      | AES_256_GCM       | RFC 5116  | 32       | 12         | 16       |
    //      | AES_128_OCB       | RFC 7253  | 16       | 1..15      | 8,12,16  |
    //      | AES_192_OCB       | RFC 7253  | 24       | 1..15      | 8,12,16  |
    //      | AES_256_OCB       | RFC 7253  | 32       | 1..15      | 8,12,16  |
    //      | CHACHA20_POLY1305 | RFC 7539  | 32       | 12         | 16       |
    //
    public abstract class AeadAlgorithm : Algorithm
    {
        private readonly int _keySize;
        private readonly int _maxNonceSize;
        private readonly int _minNonceSize;
        private readonly int _tagSize;

        internal AeadAlgorithm(
            int keySize,
            int minNonceSize,
            int maxNonceSize,
            int tagSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(minNonceSize > 0);
            Debug.Assert(maxNonceSize >= minNonceSize);
            Debug.Assert(tagSize > 0);

            _keySize = keySize;
            _minNonceSize = minNonceSize;
            _maxNonceSize = maxNonceSize;
            _tagSize = tagSize;
        }

        public int KeySize => _keySize;

        public int MaxNonceSize => _maxNonceSize;

        public int MinNonceSize => _minNonceSize;

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
            if (nonce.Length < _minNonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (nonce.Length > _maxNonceSize)
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
            if (nonce.Length < _minNonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (nonce.Length > _maxNonceSize)
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
            if (nonce.Length < _minNonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (nonce.Length > _maxNonceSize)
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
            if (nonce.Length < _minNonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (nonce.Length > _maxNonceSize)
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
            if (nonce.Length < _minNonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (nonce.Length > _maxNonceSize)
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
            if (nonce.Length < _minNonceSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(nonce));
            if (nonce.Length > _maxNonceSize)
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
