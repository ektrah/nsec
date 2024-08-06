using System;
using System.Diagnostics;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  An authenticated encryption with associated data (AEAD) algorithm
    //
    //  Candidates
    //
    //      | Algorithm          | Reference | Key Size | Nonce Size | Tag Size | Max. Plaintext Size |
    //      | ------------------ | --------- | -------- | ---------- | -------- | ------------------- |
    //      | AES-256-GCM        | RFC 5116  | 32       | 12         | 16       | 2^36-31             |
    //
    public abstract class AeadDetachedAlgorithm : Algorithm
    {
        private static Aes256GcmDetached? s_Aes256Gcm;

        private readonly int _keySize;
        private readonly int _nonceSize;
        private readonly int _tagSize;

        private protected AeadDetachedAlgorithm(
            int keySize,
            int nonceSize,
            int tagSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(nonceSize >= 0 && nonceSize <= 32);
            Debug.Assert(tagSize >= 0 && tagSize <= 255);

            _keySize = keySize;
            _nonceSize = nonceSize;
            _tagSize = tagSize;
        }

        public static Aes256GcmDetached Aes256Gcm
        {
            get
            {
                Aes256GcmDetached? instance = s_Aes256Gcm;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Aes256Gcm, new Aes256GcmDetached(), null);
                    instance = s_Aes256Gcm;
                }
                return instance;
            }
        }

        public int KeySize => _keySize;

        public int NonceSize => _nonceSize;

        public int TagSize => _tagSize;

        public void Encrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }
            if (ciphertext.Length != plaintext.Length)
            {
                throw Error.Argument_CiphertextLength(nameof(ciphertext));
            }
            if (ciphertext.Overlaps(plaintext, out int offset) && offset != 0)
            {
                throw Error.Argument_OverlapCiphertext(nameof(ciphertext));
            }
            if (tag.Length != _tagSize)
            {
                throw Error.Argument_TagLength(nameof(tag), _tagSize);
            }

            EncryptCore(key.Handle, nonce, associatedData, plaintext, ciphertext, tag);
        }

        public bool Decrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != _nonceSize)
            {
                return false;
            }
            if (tag.Length != _tagSize)
            {
                throw Error.Argument_TagLength(nameof(tag), _tagSize);
            }
            if (plaintext.Length != ciphertext.Length)
            {
                throw Error.Argument_PlaintextLength(nameof(plaintext));
            }
            if (plaintext.Overlaps(ciphertext, out int offset) && offset != 0)
            {
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));
            }

            return DecryptCore(key.Handle, nonce, associatedData, ciphertext, tag, plaintext);
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
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag);

        private protected abstract bool DecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext);
    }
}
