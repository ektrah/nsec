using System;
using System.Diagnostics;
using NSec.Cryptography;
using static Interop.Libsodium;

namespace NSec.Experimental.Sodium
{
    public abstract class NaclSecretBoxAlgorithm : Algorithm
    {
        private readonly int _keySize;
        private readonly int _macSize;
        private readonly int _nonceSize;

        private protected NaclSecretBoxAlgorithm(
            int keySize,
            int nonceSize,
            int macSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(nonceSize >= 0 && nonceSize <= Nonce.MaxSize);
            Debug.Assert(macSize >= 0);

            _keySize = keySize;
            _nonceSize = nonceSize;
            _macSize = macSize;
        }

        public int KeySize => _keySize;

        public int MacSize => _macSize;

        public int NonceSize => _nonceSize;

        public byte[] Decrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _macSize)
                throw Error.Cryptographic_DecryptionFailed();

            byte[] plaintext = new byte[ciphertext.Length - _macSize];

            if (!TryDecryptCore(key.Handle, nonce, ciphertext, plaintext))
            {
                throw Error.Cryptographic_DecryptionFailed();
            }

            return plaintext;
        }

        public void Decrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _macSize)
                throw Error.Cryptographic_DecryptionFailed();
            if (plaintext.Length != ciphertext.Length - _macSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));
            if (plaintext.Overlaps(ciphertext))
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));

            if (!TryDecryptCore(key.Handle, nonce, ciphertext, plaintext))
            {
                throw Error.Cryptographic_DecryptionFailed();
            }
        }

        public byte[] Encrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (plaintext.Length > int.MaxValue - _macSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), (int.MaxValue - _macSize).ToString());

            byte[] ciphertext = new byte[_macSize + plaintext.Length];
            EncryptCore(key.Handle, nonce, plaintext, ciphertext);
            return ciphertext;
        }

        public void Encrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (plaintext.Length > int.MaxValue - _macSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), (int.MaxValue - _macSize).ToString());
            if (ciphertext.Length != _macSize + plaintext.Length)
                throw Error.Argument_CiphertextLength(nameof(ciphertext));
            if (ciphertext.Overlaps(plaintext))
                throw Error.Argument_OverlapCiphertext(nameof(ciphertext));

            EncryptCore(key.Handle, nonce, plaintext, ciphertext);
        }

        public bool TryDecrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            out byte[] plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());

            if (ciphertext.Length < _macSize)
            {
                plaintext = null;
                return false;
            }

            byte[] result = new byte[ciphertext.Length - _macSize];
            bool success = TryDecryptCore(key.Handle, nonce, ciphertext, result);
            plaintext = success ? result : null;
            return success;
        }

        public bool TryDecrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize.ToString());
            if (ciphertext.Length < _macSize)
                return false;
            if (plaintext.Length != ciphertext.Length - _macSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));
            if (plaintext.Overlaps(ciphertext))
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));

            return TryDecryptCore(key.Handle, nonce, ciphertext, plaintext);
        }

        internal abstract void EncryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext);

        internal abstract bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext);
    }
}
