using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
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
    //      | ChaCha20-Poly1305  | RFC 7539  | 32       | 12         | 16       | 2^38-64             |
    //      | AES-128-CCM        | RFC 5116  | 16       | 12         | 16       | 2^24-1              |
    //      | AES-256-CCM        | RFC 5116  | 32       | 12         | 16       | 2^24-1              |
    //      | AES-128-GCM        | RFC 5116  | 16       | 12         | 16       | 2^36-31             |
    //      | AES-256-GCM        | RFC 5116  | 32       | 12         | 16       | 2^36-31             |
    //      | AES-128-OCB        | RFC 7253  | 16       | 1..15      | 8,12,16  | unbounded           |
    //      | AES-192-OCB        | RFC 7253  | 24       | 1..15      | 8,12,16  | unbounded           |
    //      | AES-256-OCB        | RFC 7253  | 32       | 1..15      | 8,12,16  | unbounded           |
    //      | AES-CCM-16-64-128  | RFC 8152  | 16       | 13         | 8        | 2^16-1              |
    //      | AES-CCM-16-64-256  | RFC 8152  | 32       | 13         | 8        | 2^16-1              |
    //      | AES-CCM-64-64-128  | RFC 8152  | 16       | 7          | 8        | 2^64-1              |
    //      | AES-CCM-64-64-256  | RFC 8152  | 32       | 7          | 8        | 2^64-1              |
    //      | AES-CCM-16-128-128 | RFC 8152  | 16       | 13         | 16       | 2^16-1              |
    //      | AES-CCM-16-128-256 | RFC 8152  | 32       | 13         | 16       | 2^16-1              |
    //      | AES-CCM-64-128-128 | RFC 8152  | 16       | 7          | 16       | 2^64-1              |
    //      | AES-CCM-64-128-256 | RFC 8152  | 32       | 7          | 16       | 2^64-1              |
    //
    public abstract class AeadAlgorithm : Algorithm
    {
        private readonly int _keySize;
        private readonly int _maxPlaintextSize;
        private readonly int _nonceSize;
        private readonly int _tagSize;

        private protected AeadAlgorithm(
            int keySize,
            int nonceSize,
            int tagSize,
            int maxPlaintextSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(nonceSize >= 0 && nonceSize <= Nonce.MaxSize);
            Debug.Assert(tagSize >= 0 && tagSize <= 255);
            Debug.Assert(maxPlaintextSize >= 65535 && maxPlaintextSize <= int.MaxValue - tagSize);

            _keySize = keySize;
            _nonceSize = nonceSize;
            _tagSize = tagSize;
            _maxPlaintextSize = maxPlaintextSize;
        }

        public int KeySize => _keySize;

        public int MaxPlaintextSize => _maxPlaintextSize;

        public int NonceSize => _nonceSize;

        public int TagSize => _tagSize;

        public byte[] Decrypt(
            Key key,
            Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _tagSize || ciphertext.Length - _tagSize > _maxPlaintextSize)
                throw Error.Cryptographic_DecryptionFailed();

            byte[] plaintext = new byte[ciphertext.Length - _tagSize];

            if (!TryDecryptCore(key.Handle, ref nonce, associatedData, ciphertext, plaintext))
            {
                throw Error.Cryptographic_DecryptionFailed();
            }

            return plaintext;
        }

        public void Decrypt(
            Key key,
            Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _tagSize || ciphertext.Length - _tagSize > _maxPlaintextSize)
                throw Error.Cryptographic_DecryptionFailed();
            if (plaintext.Length != ciphertext.Length - _tagSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));
            if (Utilities.Overlap(plaintext, ciphertext, out IntPtr byteOffset) && byteOffset != IntPtr.Zero)
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));

            if (!TryDecryptCore(key.Handle, ref nonce, associatedData, ciphertext, plaintext))
            {
                throw Error.Cryptographic_DecryptionFailed();
            }
        }

        public byte[] Encrypt(
            Key key,
            Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (plaintext.Length > _maxPlaintextSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), _maxPlaintextSize.ToString());

            byte[] ciphertext = new byte[plaintext.Length + _tagSize];
            EncryptCore(key.Handle, ref nonce, associatedData, plaintext, ciphertext);
            return ciphertext;
        }

        public void Encrypt(
            Key key,
            Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (plaintext.Length > _maxPlaintextSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), _maxPlaintextSize.ToString());
            if (ciphertext.Length != plaintext.Length + _tagSize)
                throw Error.Argument_CiphertextLength(nameof(ciphertext));
            if (Utilities.Overlap(ciphertext, plaintext, out IntPtr byteOffset) && byteOffset != IntPtr.Zero)
                throw Error.Argument_OverlapCiphertext(nameof(ciphertext));

            EncryptCore(key.Handle, ref nonce, associatedData, plaintext, ciphertext);
        }

        public bool TryDecrypt(
            Key key,
            Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            out byte[] plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());

            if (ciphertext.Length < _tagSize || ciphertext.Length - _tagSize > _maxPlaintextSize)
            {
                plaintext = null;
                return false;
            }

            byte[] result = new byte[ciphertext.Length - _tagSize];
            bool success = TryDecryptCore(key.Handle, ref nonce, associatedData, ciphertext, result);
            plaintext = success ? result : null;
            return success;
        }

        public bool TryDecrypt(
            Key key,
            Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _tagSize || ciphertext.Length - _tagSize > _maxPlaintextSize)
                return false;
            if (plaintext.Length != ciphertext.Length - _tagSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));
            if (Utilities.Overlap(plaintext, ciphertext, out IntPtr byteOffset) && byteOffset != IntPtr.Zero)
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));

            return TryDecryptCore(key.Handle, ref nonce, associatedData, ciphertext, plaintext);
        }

        private protected abstract void EncryptCore(
            SecureMemoryHandle keyHandle,
            ref Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext);

        private protected abstract bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            ref Nonce nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext);

        internal abstract bool TryReadAlgorithmIdentifier(
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> nonce);

        internal abstract void WriteAlgorithmIdentifier(
            ref Asn1Writer writer,
            ReadOnlySpan<byte> nonce);
    }
}
