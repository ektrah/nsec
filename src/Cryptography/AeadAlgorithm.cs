using System;
using System.Diagnostics;
using System.Threading;

namespace NSec.Cryptography
{
    //
    //  An authenticated encryption with associated data (AEAD) algorithm
    //
    //  Candidates
    //
    //      | Algorithm          | Reference | Key Size | Nonce Size | Tag Size | Max. Plaintext Size |
    //      | ------------------ | --------- | -------- | ---------- | -------- | ------------------- |
    //      | ChaCha20-Poly1305  | RFC 8439  | 32       | 12         | 16       | 2^38-64             |
    //      | AES-128-CCM        | RFC 5116  | 16       | 12         | 16       | 2^24-1              |
    //      | AES-256-CCM        | RFC 5116  | 32       | 12         | 16       | 2^24-1              |
    //      | AES-128-GCM        | RFC 5116  | 16       | 12         | 16       | 2^36-31             |
    //      | AES-256-GCM        | RFC 5116  | 32       | 12         | 16       | 2^36-31             |
    //      | AES-128-OCB        | RFC 7253  | 16       | 1..15      | 8,12,16  | unbounded           |
    //      | AES-192-OCB        | RFC 7253  | 24       | 1..15      | 8,12,16  | unbounded           |
    //      | AES-256-OCB        | RFC 7253  | 32       | 1..15      | 8,12,16  | unbounded           |
    //
    public abstract class AeadAlgorithm : Algorithm
    {
        private static Aes256Gcm? s_Aes256Gcm;
        private static ChaCha20Poly1305? s_ChaCha20Poly1305;

        private readonly int _keySize;
        private readonly int _nonceSize;
        private readonly int _tagSize;

        private protected AeadAlgorithm(
            int keySize,
            int nonceSize,
            int tagSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(nonceSize >= 0 && nonceSize <= Nonce.MaxSize);
            Debug.Assert(tagSize >= 0 && tagSize <= 255);

            _keySize = keySize;
            _nonceSize = nonceSize;
            _tagSize = tagSize;
        }

        public static Aes256Gcm Aes256Gcm
        {
            get
            {
                Aes256Gcm? instance = s_Aes256Gcm;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Aes256Gcm, new Aes256Gcm(), null);
                    instance = s_Aes256Gcm;
                }
                return instance;
            }
        }

        public static ChaCha20Poly1305 ChaCha20Poly1305
        {
            get
            {
                ChaCha20Poly1305? instance = s_ChaCha20Poly1305;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_ChaCha20Poly1305, new ChaCha20Poly1305(), null);
                    instance = s_ChaCha20Poly1305;
                }
                return instance;
            }
        }

        public int KeySize => _keySize;

        public int NonceSize => _nonceSize;

        public int TagSize => _tagSize;

        public byte[] Encrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (plaintext.Length > int.MaxValue - _tagSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), int.MaxValue - _tagSize);

            byte[] ciphertext = new byte[plaintext.Length + _tagSize];
            EncryptCore(key.Span, in nonce, associatedData, plaintext, ciphertext);
            return ciphertext;
        }

        public void Encrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (ciphertext.Length - _tagSize != plaintext.Length)
                throw Error.Argument_CiphertextLength(nameof(ciphertext));
            if (ciphertext.Overlaps(plaintext, out int offset) && offset != 0)
                throw Error.Argument_OverlapCiphertext(nameof(ciphertext));

            EncryptCore(key.Span, in nonce, associatedData, plaintext, ciphertext);
        }

        public bool Decrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            out byte[]? plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));

            if (nonce.Size != _nonceSize || ciphertext.Length < _tagSize)
            {
                plaintext = null;
                return false;
            }

            byte[] result = new byte[ciphertext.Length - _tagSize];
            bool success = DecryptCore(key.Span, in nonce, associatedData, ciphertext, result);
            plaintext = success ? result : null;
            return success;
        }

        public bool Decrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Size != _nonceSize || ciphertext.Length < _tagSize)
                return false;
            if (plaintext.Length != ciphertext.Length - _tagSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));
            if (plaintext.Overlaps(ciphertext, out int offset) && offset != 0)
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));

            return DecryptCore(key.Span, in nonce, associatedData, ciphertext, plaintext);
        }

        internal sealed override int GetKeySize()
        {
            return _keySize;
        }

        internal sealed override int GetPublicKeySize()
        {
            throw Error.InvalidOperation_InternalError();
        }

        internal abstract override int GetSeedSize();

        private protected abstract void EncryptCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext);

        private protected abstract bool DecryptCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext);
    }
}
