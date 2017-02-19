using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _tagSize)
                throw Error.Cryptographic_DecryptionFailed();

            byte[] plaintext = new byte[ciphertext.Length - _tagSize];

            if (!TryDecryptCore(key.Handle, nonce, associatedData, ciphertext, plaintext))
            {
                throw Error.Cryptographic_DecryptionFailed();
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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _tagSize)
                throw Error.Cryptographic_DecryptionFailed();
            if (plaintext.Length != ciphertext.Length - _tagSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));

            if (!TryDecryptCore(key.Handle, nonce, associatedData, ciphertext, plaintext))
            {
                throw Error.Cryptographic_DecryptionFailed();
            }
        }

        public byte[] Encrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (int.MaxValue - plaintext.Length < _tagSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext));

            byte[] ciphertext = new byte[plaintext.Length + _tagSize];
            EncryptCore(key.Handle, nonce, associatedData, plaintext, ciphertext);
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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (int.MaxValue - plaintext.Length < _tagSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext));
            if (ciphertext.Length != plaintext.Length + _tagSize)
                throw Error.Argument_CiphertextLength(nameof(ciphertext));

            EncryptCore(key.Handle, nonce, associatedData, plaintext, ciphertext);
        }

        public bool TryDecrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            out byte[] plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());

            if (ciphertext.Length < _tagSize)
            {
                plaintext = null;
                return false;
            }

            byte[] result = new byte[ciphertext.Length - _tagSize];

            if (!TryDecryptCore(key.Handle, nonce, associatedData, ciphertext, result))
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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _tagSize)
                return false;
            if (plaintext.Length != ciphertext.Length - _tagSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));

            return TryDecryptCore(key.Handle, nonce, associatedData, ciphertext, plaintext);
        }

        internal abstract void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext);

        internal abstract bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext);

        internal virtual bool TryReadAlgorithmIdentifier(
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> nonce)
        {
            throw Error.NotSupported_Operation();
        }

        internal virtual void WriteAlgorithmIdentifier(
            ref Asn1Writer writer,
            ReadOnlySpan<byte> nonce)
        {
            throw Error.NotSupported_Operation();
        }
    }
}
